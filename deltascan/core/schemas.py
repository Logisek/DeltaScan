from marshmallow import Schema, fields, pre_load, post_load

class PortScanPorts(Schema):
    portid = fields.Str(required=True)
    state = fields.Str(required=True)
    service = fields.Str(required=True)
    serviceProduct = fields.Str(required=True)

class PortScan(Schema):
    host = fields.Str(required=True)
    status = fields.Str(required=True)
    ports = fields.Nested(PortScanPorts, many=True, required=True)

class DBPortScan(Schema):
    id = fields.Int(required=True)
    host = fields.Str(required=True)
    profile_name = fields.Str(required=True)
    results  = fields.Dict(required=True)
    result_hash = fields.Str(required=True)
    created_at = fields.Str(required=True)

    @pre_load
    def pre_load(self, data, **kwargs):
        if data["created_at"]:
            data["created_at"] = str(data["created_at"])
        return data