import asyncio
import struct
from time import time


# Valores das flags que serão usadas na nossa implementação simplificada
FLAGS_FIN = 1<<0
FLAGS_SYN = 1<<1
FLAGS_RST = 1<<2
FLAGS_ACK = 1<<4

MSS = 1460   # Tamanho do payload de um segmento TCP (em bytes)

def make_header(src_port, dst_port, seq_no, ack_no, flags):
    """
    Constrói um cabeçalho TCP simplificado.

    Consulte o formato completo em https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
    """
    return struct.pack('!HHIIHHHH',
                       src_port, dst_port, seq_no, ack_no, (5 << 12) | flags,
                       8*MSS, 0, 0)


def read_header(segment):
    """
    Lê um cabeçalho
    """
    src_port, dst_port, seq_no, ack_no, \
        flags, window_size, checksum, urg_ptr = \
        struct.unpack('!HHIIHHHH', segment[:20])
    return src_port, dst_port, seq_no, ack_no, \
        flags, window_size, checksum, urg_ptr


def calc_checksum(segment, src_addr=None, dst_addr=None):
    """
    Calcula o checksum complemento-de-um (formato do TCP e do UDP) para os
    dados fornecidos.

    É necessário passar os endereços IPv4 de origem e de destino, já que
    apesar de não fazerem parte da camada de transporte, eles são incluídos
    no pseudocabeçalho, que faz parte do cálculo do checksum.

    Os endereços IPv4 devem ser passados como string (no formato x.y.z.w)
    """
    if src_addr is None and dst_addr is None:
        data = segment
    else:
        pseudohdr = str2addr(src_addr) + str2addr(dst_addr) + \
            struct.pack('!HH', 0x0006, len(segment))
        data = pseudohdr + segment

    if len(data) % 2 == 1:
        # se for ímpar, faz padding à direita
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        x, = struct.unpack('!H', data[i:i+2])
        checksum += x
        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + 1
    checksum = ~checksum
    return checksum & 0xffff


def fix_checksum(segment, src_addr, dst_addr):
    """
    Corrige o checksum de um segmento TCP.
    """
    seg = bytearray(segment)
    seg[16:18] = b'\x00\x00'
    seg[16:18] = struct.pack('!H', calc_checksum(seg, src_addr, dst_addr))
    return bytes(seg)


def addr2str(addr):
    """
    Converte um endereço IPv4 binário para uma string (no formato x.y.z.w)
    """
    return '%d.%d.%d.%d' % tuple(int(x) for x in addr)


def str2addr(addr):
    """
    Converte uma string (no formato x.y.z.w) para um endereço IPv4 binário
    """
    return bytes(int(x) for x in addr.split('.'))


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

        #passo 1 implementado aqui 
        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no)

            flags = flags & 0
            flags = flags | (FLAGS_SYN | FLAGS_ACK)

            ack_no = seq_no + 1

            segmento = make_header(dst_port, src_port, seq_no, ack_no, flags)
            segmento_checked = fix_checksum(segmento, dst_addr, src_addr)

            self.rede.enviar(segmento_checked, src_addr)

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None

        self.no = b""
        self.seq_no = seq_no
        self.ack_no = seq_no + 1
        self.seq_no_base = seq_no + 1
        self.timer = None
        self.timeoutInterval = 1
        self.EstimatedRTT = 1
        self.DevRTT = 0.5
        self.janela_congestionamento = MSS  
        self.duplicatas_acks = 0  

        self.pacotes_sem_ack = []
        self.timer_r = False

        self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
 

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

    def _calculate_timeout_interval(self, sampleRTT):
        alpha = 0.125
        beta = 0.25

        self.EstimatedRTT = (1 - alpha) * self.EstimatedRTT + alpha * sampleRTT
        self.DevRTT = (1 - beta) * self.DevRTT + beta * abs(sampleRTT - self.EstimatedRTT)

        self.timeoutInterval = self.EstimatedRTT + 4 * self.DevRTT

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.ack_no = self.ack_no + 1

            segmento = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
            segmento_checked = fix_checksum(segmento, dst_addr, src_addr)

            self.servidor.rede.enviar(segmento_checked, src_addr)
            print(self.servidor.conexoes)

            del self.servidor.conexoes[self.id_conexao]
            self.callback(self, b"")

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

            if ack_no < self.seq_no_base:
                # ainda há pacotes a serem recebidos, start timer
                self.timer_r = True
                self.timer = asyncio.get_event_loop().call_later(1, self.timer_run)

            return
        
        if seq_no != self.ack_no:
            return
        
        # Medir o tempo de início do timer
        self.timer_start_time = time()

        self.ack_no = len(payload) + self.ack_no

        self.seq_no = ack_no
        segmento = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
        segmento_checked = fix_checksum(segmento, dst_addr, src_addr)

        self.servidor.rede.enviar(segmento_checked, src_addr)

        self.callback(self, payload)

    def timer_run(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        segmento = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK)
        segmento_checked = fix_checksum(segmento, dst_addr, src_addr)

        payload = self.no[:MSS]

        self.servidor.rede.enviar(segmento_checked + payload, src_addr)

        self.timer_start_time = time()

        self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self.timer_run)

        # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback
        

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        i = 0
        while i < int(len(dados) / MSS):
            inicio = i * MSS
            fim = min(len(dados), (i + 1) * MSS)

            segmento = make_header(dst_port, src_port, self.seq_no_base, self.ack_no, FLAGS_ACK)

            payload = dados[inicio : fim]
            segmento_checked = fix_checksum(segmento + payload, dst_addr, src_addr)

            self.servidor.rede.enviar(segmento_checked, src_addr)
            self.seq_no_base = len(payload) + self.seq_no_base
            self.no += payload

            if not self.timer_r:
                self.timer_r = True
                self.timer = asyncio.get_event_loop().call_later(1, self.timer_run)

            i += 1

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        segmento = make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN)
        segmento_checked = fix_checksum(segmento, dst_addr, src_addr)

        self.servidor.rede.enviar(segmento_checked, src_addr)