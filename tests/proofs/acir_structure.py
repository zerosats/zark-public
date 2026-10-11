"""Read-only structure inspection of the pinned Noir beta.25 ACIR encoding.

BB's local `acir_roundtrip` CLI identifies its input as MessagePack ACIR. The
format consumed here is deliberately narrow: version byte 3, then a two-item
program array, with six-item named circuit records. Unknown layouts fail closed.
Counts are cross-checked against both nargo's ACIR dump and BB's opcode count.
This decoder never executes bytecode or accepts it as a proof.
"""
import base64,gzip,json,struct
from collections import Counter

class MessagePack:
    def __init__(self,data):self.data=data;self.at=0
    def take(self,n):
        end=self.at+n;assert end<=len(self.data),'truncated MessagePack'
        value=self.data[self.at:end];self.at=end;return value
    def uint(self,n):return int.from_bytes(self.take(n),'big')
    def array(self):
        tag=self.uint(1)
        if 0x90<=tag<=0x9f:return tag&15
        assert tag in (0xdc,0xdd),('expected array',hex(tag))
        return self.uint(2 if tag==0xdc else 4)
    def value(self,keep=True,depth=0):
        assert depth<128,'nested MessagePack limit'
        tag=self.uint(1)
        if tag<=0x7f:return tag if keep else None
        if tag>=0xe0:return tag-256 if keep else None
        if tag in (0xc0,0xc2,0xc3):return {0xc0:None,0xc2:False,0xc3:True}[tag] if keep else None
        if 0xcc<=tag<=0xcf or 0xd0<=tag<=0xd3:
            signed=tag>=0xd0;n=1<<(tag-(0xd0 if signed else 0xcc));data=self.take(n)
            return int.from_bytes(data,'big',signed=signed) if keep else None
        if tag in (0xca,0xcb):
            data=self.take(4 if tag==0xca else 8)
            return struct.unpack('>f' if tag==0xca else '>d',data)[0] if keep else None
        if 0xa0<=tag<=0xbf or tag in (0xd9,0xda,0xdb,0xc4,0xc5,0xc6):
            n=tag&31 if 0xa0<=tag<=0xbf else self.uint({0xd9:1,0xda:2,0xdb:4,0xc4:1,0xc5:2,0xc6:4}[tag])
            value=self.take(n)
            return (value if tag in (0xc4,0xc5,0xc6) else value.decode()) if keep else None
        if 0x90<=tag<=0x9f or tag in (0xdc,0xdd):
            n=tag&15 if 0x90<=tag<=0x9f else self.uint(2 if tag==0xdc else 4)
            if keep:return [self.value(True,depth+1) for _ in range(n)]
            for _ in range(n):self.value(False,depth+1)
            return None
        if 0x80<=tag<=0x8f or tag in (0xde,0xdf):
            n=tag&15 if 0x80<=tag<=0x8f else self.uint(2 if tag==0xde else 4)
            if keep:
                result={}
                for _ in range(n):
                    key=self.value(True,depth+1);assert key not in result,'duplicate MessagePack map key'
                    result[key]=self.value(True,depth+1)
                return result
            for _ in range(n):self.value(False,depth+1);self.value(False,depth+1)
            return None
        raise AssertionError(('unsupported MessagePack tag',hex(tag)))

def inspect(path):
    packed=base64.b64decode(json.loads(path.read_text())['bytecode']);raw=gzip.decompress(packed)
    reader=MessagePack(raw);assert reader.uint(1)==3,'unknown ACIR encoding version'
    assert reader.array()==2,'unknown ACIR program layout'
    functions=[]
    for _ in range(reader.array()):
        assert reader.array()==6,'unknown ACIR function layout'
        name=reader.value();assert isinstance(name,str)
        count=reader.array();blackboxes=Counter();recursions=[]
        for _ in range(count):
            opcode=reader.value();assert isinstance(opcode,dict) and len(opcode)==1
            if 'BlackBoxFuncCall' in opcode:
                box=opcode['BlackBoxFuncCall'];assert isinstance(box,dict) and len(box)==1
                kind,payload=next(iter(box.items()));blackboxes[kind]+=1
                if 'RECURSIVE' in kind.upper():recursions.append(dict(kind=kind,payload=payload))
        for _ in range(4):reader.value(False)
        functions.append(dict(name=name,acir_opcodes=count,blackboxes=dict(blackboxes),recursions=recursions))
    reader.value(False)
    assert reader.at==len(raw),'unparsed ACIR bytes'
    return dict(encoding_version=3,compressed_bytes=len(packed),uncompressed_bytes=len(raw),functions=functions)
