from marshmallow import Schema, fields, pre_load, post_load

class Config(Schema):
    output_file = fields.Str(allow_none=True)

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


class DBScan(Schema): # TODO: rename DBScan to ScanFromDB
    id = fields.Int(required=True)
    host = fields.Str(required=True)
    profile_name = fields.Str(required=True)
    arguments = fields.Str(required=True)
    results  = fields.Nested(Scan, required=True)
    result_hash = fields.Str(required=True)
    created_at = fields.Str(required=True)

    @pre_load
    def pre_load(self, data, **kwargs):
        if isinstance(data, dict) and "created_at" in data:
            data["created_at"] = str(data["created_at"])
        return data
    
class ReportScanFromDB(Schema):
    id = fields.Int(required=True)
    host = fields.Str(required=True)
    profile_name = fields.Str(required=True)
    arguments = fields.Str(required=True)
    results  = fields.Nested(Scan, required=True)
    result_hash = fields.Str(required=True)
    created_at = fields.Str(required=True)

    @pre_load
    def pre_load(self, data, **kwargs):
        if isinstance(data, dict) and "created_at" in data:
            data["created_at"] = str(data["created_at"])
        return data
    
    @post_load
    def post_load(self, data, **kwargs):
        if isinstance(data, dict) and "id" in data:
            del data["id"]
        return data
    
class ReportDiffs(Schema):
    date_from = fields.Str(required=True)
    date_to = fields.Str(required=True)
    entity_name = fields.Str(required=True)
    entity_value = fields.Str(required=True)
    entity_change_type = fields.Str(required=True)
    entity_change_value_from = fields.Str(required=True)
    entity_change_value_to = fields.Str(required=True)
    
class Diffs(Schema):
    ids = fields.List(fields.Int(), required=True)
    dates = fields.List(fields.Str(), required=True)
    diffs = fields.Dict(required=True)
    result_hash = fields.List(fields.Str(), required=True)
