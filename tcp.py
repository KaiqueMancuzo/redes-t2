import asyncio
from curses import flash
from sys import flags
from tcputils import *
from time import time

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return


        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        #  FIN flag
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            conexao = self.conexoes[id_conexao]
            conexao.registrar_recebedor(b'')  # Chamar o método correto

            flags = FLAGS_ACK
            segmento = make_header(src_port, dst_port, conexao.seq_no_base, conexao.ack_no, flags)
            segmento_checksum_corrigido = fix_checksum(segmento, src_addr, dst_addr)
            self.rede.enviar(segmento_checksum_corrigido, dst_addr)

            conexao.seq_no_base += 1

            flags = FLAGS_FIN | FLAGS_ACK
            segmento = make_header(src_port, dst_port, conexao.seq_no_base, conexao.ack_no, flags)
            segmento_checksum_corrigido = fix_checksum(segmento, src_addr, dst_addr)
            self.rede.enviar(segmento_checksum_corrigido, dst_addr)

            conexao.seq_no_base += 1

            asyncio.get_event_loop().run_until_complete(self.esperar_ack())
          
        if (flags & FLAGS_SYN) == FLAGS_SYN:

            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao)
            
            flags = flags & 0
            flags = flags | (FLAGS_SYN | FLAGS_ACK)

           
            conexao.seq_no = (seq_no + 1) % 0x10000
            conexao.ack_no = seq_no + 1
            
        
            src_addr, dst_addr = dst_addr, src_addr
            src_port, dst_port = dst_port, src_port

            segmento = make_header(src_port, dst_port, conexao.seq_no, conexao.ack_no, flags)
            segmento_checked = fix_checksum(segmento, src_addr, dst_addr)
            self.rede.enviar(segmento_checked, dst_addr)
            

            conexao.seq_no += 1
            conexao.seq_no_base = conexao.seq_no
            
            if self.callback:
                self.callback(conexao)

        elif id_conexao in self.conexoes:
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        # Conexão desconhecida
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                (src_addr, src_port, dst_addr, dst_port))

class Conexao:
    def __init__(self, servidor, id_conexao):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.fila_envio = []
        self.cwnd = 1
        self.sent_pkts = []
        self.pktsQ = []
        self.DevRTT = 0.5
        self.janela_congestionamento = MSS  
        self.timeoutInterval = 1
        self.seq_no = None
        self.ack_no = None
        self.seq_no_base = None
        self.pacotes_sem_ack = []
        self.estimatedRTT = None

    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        print('Este é um exemplo de como fazer um timer')


    def _start_timer(self):
        # Cancelar o timer existente (se estiver rodando)
        if self.timer is not None:
            self.timer.cancel()

        # Iniciar um novo timer
        self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self.timer_run)
        self.timer_r = True

    def _timer(self):
        if self.pacotes_sem_ack:
            segmento, _, dst_addr, _ = self.pacotes_sem_ack[0]

            self.servidor.rede.enviar(segmento, dst_addr)
            self.pacotes_sem_ack[0][3] = None

    def _ack_pkt(self, ack_no):
        if len(self.sent_pkts) == 0:
            return
        self.cwnd += 1
        idx = self._get_idx(ack_no)
        _, t0 = self.sent_pkts[idx]
        del self.sent_pkts[:idx + 1]
        if t0 is not None:
            self.timeoutInterval = self.timeout_Interval(t0, time.time())
        if len(self.sent_pkts) == 0:
            self.timer.cancel()
            self._send_window()

    def timeout_interval(self):
        _, _, _, sampleRTT = self.pacotes_sem_ack[0]
        if sampleRTT is None:
            return

        sampleRTT = round(time(), 5) - sampleRTT
        if self.estimatedRTT is None:
            self.estimatedRTT = sampleRTT
            self.devRTT = sampleRTT / 2
        else:
            alpha = 0.125
            beta = 0.25

            self.estimatedRTT = (1 - alpha) * self.estimatedRTT + alpha * sampleRTT
            self.devRTT = (1 - beta) * self.devRTT + beta * abs(sampleRTT - self.estimatedRTT)

        self.timeoutInterval = self.estimatedRTT + 4 * self.devRTT

    async def esperar_ack(self):
        while self.pacotes_sem_ack:
            await asyncio.sleep(0.1)  # Aguarda por um curto período de tempo
            if self.pacotes_sem_ack:
                segmento, _, dst_addr, timestamp = self.pacotes_sem_ack[0]
                current_time = time()
                if timestamp is not None and current_time - timestamp > self.timeoutInterval:
                    self.servidor.rede.enviar(segmento, dst_addr)
                    self.pacotes_sem_ack[0][3] = current_time
                    # Aqui você também pode ajustar a lógica do cálculo de timeoutInterval
                else:
                    break

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):

        if (flags & FLAGS_ACK) == FLAGS_ACK and ack_no > self.seq_no_base:
            self.seq_no_base = ack_no
            if self.pacotes_sem_ack:
                self.timeout_interval()
                self.timer.cancel()
                self.pacotes_sem_ack.pop(0)
                if self.pacotes_sem_ack:
                    self.cwnd = max(1, self.cwnd // 2)
                    self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._timer)
        
        src_addr, _, dst_addr, _ = self.id_conexao
        
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            payload = b''
            self.ack_no += 1
        elif len(payload) <= 0:
            return

        if seq_no != self.ack_no:
            return
        self.callback(self, payload)
        self.ack_no += len(payload)

        dst_addr, dst_port, src_addr, src_port = self.id_conexao

        segmento = make_header(src_port, dst_port, self.seq_no_base, self.ack_no, FLAGS_ACK)
        segmento_checked = fix_checksum(segmento, src_addr, dst_addr)
        self.servidor.rede.enviar(segmento_checked, dst_addr)

        if len(self.sent_pkts) != 0:
            self._ack_pkt(ack_no)

        if (len(payload) == 0) and ((flags & FLAGS_ACK) == FLAGS_ACK):
            self.timer.cancel()
            self.timer_r = False

            if ack_no == self.seq_no:
                self.duplicatas_acks += 1
            else:

                self.duplicatas_acks = 0
            #   self.seq_no = ack_no
            #   self.no = self.no[ack_no - self.seq_no_base:]

            # Verificar se a janela de congestionamento pode ser aumentada
                if ack_no >= self.seq_no_base + self.janela_congestionamento:
                    self.janela_congestionamento += MSS

                # Reiniciar o timer se houver pacotes não confirmados
                if self.timer_r or len(self.no) > 0:
                    self._start_timer()

            self.no = self.no[ack_no - self.seq_no :]
            self.seq_no = ack_no
    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def _send_window(self):
        if len(self.pktsQ) == 0:
            return
        i = 0
        while i < self.cwnd and len(self.pktsQ) != 0:
            package = self.pktsQ.pop(0)
            self.sent_pkts.append((package, time.time()))
            _, _, seq, ack, _, _, _, _ = read_header(package)
            self.servidor.rede.enviar(package, self.dst_addr)
            i += 1
        if self.timer is not None:
            self.timer.cancel()
        self.timer = asyncio.get_event_loop().call_later(self.timeounterval, self._timer)

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        dst_addr, dst_port, src_addr, src_port = self.id_conexao

        flags = 0 | FLAGS_ACK
        i = 0

        while i * MSS < len(dados):
            ini = i * MSS
            fim = min(len(dados), (i + 1) * MSS)
            payload = dados[ini:fim]

            segmento = make_header(src_port, dst_port, self.seq_no, self.ack_no, flags)
            segmento_checksum_corrigido = fix_checksum(segmento + payload, src_addr, dst_addr)

            self.servidor.rede.enviar(segmento_checksum_corrigido, dst_addr)
            self.pacotes_sem_ack.append([segmento_checksum_corrigido, len(payload), dst_addr, round(time(), 5)])
            self.seq_no += len(payload)

            i += 1

            self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._timer)
            asyncio.get_event_loop().create_task(self.esperar_ack())  # Inicia a espera por ACK em paralelo
