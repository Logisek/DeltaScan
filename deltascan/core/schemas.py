from marshmallow import Schema, fields, pre_load, post_load

class ScanPorts(Schema):
    portid = fields.Str(required=True)
    state = fields.Str(required=True)
    service = fields.Str(required=True)
    servicefp = fields.Str(required=True)
    service_product = fields.Str(required=True)

class Scan(Schema):
    host = fields.Str(required=True)
    status = fields.Str(required=True)
    ports = fields.Nested(ScanPorts, many=True, required=True)
    os = fields.List(fields.Str(), required=True)
    osfingerprint = fields.Str(required=True)
    last_boot = fields.Str(required=True)
    traces = fields.List(fields.Str(), required=True)


class DBScan(Schema):
    id = fields.Int(required=True)
    host = fields.Str(required=True)
    profile_name = fields.Str(required=True)
    arguments = fields.Str(required=True)
    results  = fields.Nested(Scan, required=True)
    result_hash = fields.Str(required=True)
    created_at = fields.Str(required=True)

    @pre_load
    def pre_load(self, data, **kwargs):
        if data["created_at"]:
            data["created_at"] = str(data["created_at"])
        return data
    
class ExportScan(Schema):
    id = fields.Int(required=True)
    host = fields.Str(required=True)
    profile_name = fields.Str(required=True)
    arguments = fields.Str(required=True)
    results  = fields.Nested(Scan, required=True)
    result_hash = fields.Str(required=True)
    created_at = fields.Str(required=True)

    @pre_load
    def pre_load(self, data, **kwargs):
        if data["created_at"]:
            data["created_at"] = str(data["created_at"])
        return data
    
    @post_load
    def post_load(self, data, **kwargs):
        if data["id"]:
            del data["id"]
        return data