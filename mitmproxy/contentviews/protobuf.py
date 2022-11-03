import io
from typing import Optional

from kaitaistruct import KaitaiStream
from . import base
from mitmproxy.contrib.kaitaistruct import google_protobuf


def write_buf(out, wire_type, field_tag, body, indent_level):
    if body is not None:
        out.write(
            "{: <{level}}{}: {}\n".format(
                "",
                str(wire_type) + "<" + str(field_tag) + ">",
                # todo if not string then hex format
                body if isinstance(body, int) else str(body, "utf-8"),
                level=indent_level,
            )
        )
    elif field_tag is not None:
        out.write(" " * indent_level + str(wire_type) + "<" + str(field_tag) + ">" + " {\n")
    else:
        out.write(" " * indent_level + "}\n")


def _parse_proto(raw: bytes) -> list[google_protobuf.GoogleProtobuf.Pair]:
    """Parse a bytestring into protobuf pairs and make sure that all pairs have a valid wire type."""
    buf = google_protobuf.GoogleProtobuf(KaitaiStream(io.BytesIO(raw)))
    for pair in buf.pairs:
        if not isinstance(pair.wire_type, google_protobuf.GoogleProtobuf.Pair.WireTypes):
            raise ValueError("Not a protobuf.")
    return buf.pairs


def format_pbuf(raw):
    out = io.StringIO()
    stack = []
    wire_type = ""
    try:
        pairs = _parse_proto(raw)
    except:
        return False
    stack.extend([(pair, 0) for pair in pairs[::-1]])

    while len(stack):
        pair, indent_level = stack.pop()

        if pair.wire_type == pair.WireTypes.group_start:
            body = None
            wire_type = "group"
        elif pair.wire_type == pair.WireTypes.group_end:
            body = None
            pair._m_field_tag = None
        elif pair.wire_type == pair.WireTypes.len_delimited:
            body = pair.value.body
            wire_type = "binary"
            # wire_type = "packed"
            # pair1, indent_level1 = stack.pop()
            # stack.push(pair1,indent_level1)
            # todo if next type==group_start then wire_type = "packed"

        elif pair.wire_type == pair.WireTypes.varint:
            body = pair.value.value
            wire_type = "varint"
        else:
            body = pair.value
        try:
            pairs = _parse_proto(body)
            stack.extend([(pair, indent_level + 2) for pair in pairs[::-1]])
            write_buf(out, wire_type, pair.field_tag, None, indent_level)
        except:
            write_buf(out, wire_type, pair.field_tag, body, indent_level)

        if stack:
            prev_level = stack[-1][1]
        else:
            prev_level = 0

        if prev_level < indent_level:
            levels = int((indent_level - prev_level) / 2)
            for i in range(1, levels + 1):
                write_buf(out, wire_type, None, None, indent_level - i * 2)

    return out.getvalue()


class ViewProtobuf(base.View):
    """Human friendly view of protocol buffers
    The view uses the protoc compiler to decode the binary
    """

    name = "Protocol Buffer"
    __content_types = [
        "application/x-protobuf",
        "application/x-protobuffer",
        "application/x-google-protobuf",
        "application/x-google-protobuffer",
    ]

    def __call__(self, data, **metadata):
        decoded = format_pbuf(data)
        if not decoded:
            raise ValueError("Failed to parse input.")

        return "Protobuf", base.format_text(decoded)

    def render_priority(
            self, data: bytes, *, content_type: Optional[str] = None, **metadata
    ) -> float:
        return float(bool(data) and content_type in self.__content_types)
