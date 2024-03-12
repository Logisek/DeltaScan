from marshmallow import Schema, fields, pre_load, post_load
import datetime

class PortScan(Schema):
    host = fields.Str(required=True)
    # os = fields.Str(required=False)
    status = fields.Str(required=True)
    ports = fields.List(fields.Dict(), required=True)

class PortScanTimeField(fields.DateTime):
    def _deserialize(self, value, attr, data):
        print(value)
        # if isinstance(value, datetime):
        return value
        # return super()._deserialize(value, attr, data)

class DBPortScan(Schema):
    id = fields.Int(required=True)
    host = fields.Str(required=True)
    profile_name = fields.Str(required=True)
    results  = fields.Str(required=True)
    result_hash = fields.Str(required=True)
    created_at = fields.Str(required=True)

    @pre_load
    def pre_load(self, data, **kwargs):
        if data["created_at"]:
            data["created_at"] = str(data["created_at"])
        return data