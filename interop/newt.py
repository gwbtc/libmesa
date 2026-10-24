"""Bounded Newt/jam transport for the local, trusted Vere fixture socket."""
import socket

MAX_FRAME = 1024 * 1024


def cord(text):
    return int.from_bytes(text.encode('ascii'), 'little')


def jam(noun):
    value = pos = 0

    def bits(n, x):
        nonlocal value, pos
        value |= x << pos
        pos += n

    def atom(x):
        if x == 0:
            bits(1, 1)
            return
        width = x.bit_length()
        size = width.bit_length()
        bits(size + 1, 1 << size)
        bits(size - 1, width ^ (1 << (size - 1)))
        bits(width, x)

    def walk(x):
        if isinstance(x, tuple):
            bits(2, 1)
            walk(x[0])
            walk(x[1])
        else:
            bits(1, 0)
            atom(x)

    walk(noun)
    return value.to_bytes((pos + 7) // 8, 'little')


def cue(data):
    if len(data) > MAX_FRAME:
        raise ValueError('oversized jam')
    value = int.from_bytes(data, 'little')
    pos, memo = 0, {}

    def bits(n):
        nonlocal pos
        if n < 0 or pos + n > len(data) * 8:
            raise ValueError('truncated jam')
        out = (value >> pos) & ((1 << n) - 1)
        pos += n
        return out

    def atom():
        zeros = 0
        while bits(1) == 0:
            zeros += 1
            if zeros > 23:
                raise ValueError('oversized atom')
        if zeros == 0:
            return 0
        return bits((1 << (zeros - 1)) | bits(zeros - 1))

    def walk(depth=0):
        if depth > 64:
            raise ValueError('deep noun')
        start = pos
        if bits(1) == 0:
            out = atom()
        elif bits(1) == 0:
            out = (walk(depth + 1), walk(depth + 1))
        else:
            return memo[atom()]
        memo[start] = out
        return out

    out = walk()
    if pos != value.bit_length():
        raise ValueError('trailing jam')
    return out


def send(sock, noun):
    data = jam(noun)
    if len(data) > MAX_FRAME:
        raise ValueError('oversized frame')
    sock.sendall(b'\0' + len(data).to_bytes(4, 'little') + data)


class Frames:
    def __init__(self):
        self.buffer = bytearray()

    def read(self, sock):
        data = sock.recv(65536)
        if not data:
            raise EOFError('Vere socket closed')
        self.buffer.extend(data)
        out = []
        while len(self.buffer) >= 5:
            if self.buffer[0] != 0:
                raise ValueError('invalid newt version')
            size = int.from_bytes(self.buffer[1:5], 'little')
            if size > MAX_FRAME:
                raise ValueError('oversized newt')
            if len(self.buffer) < size + 5:
                break
            out.append(cue(self.buffer[5:5+size]))
            del self.buffer[:size+5]
        return out


def connect(path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(str(path))
    return sock
