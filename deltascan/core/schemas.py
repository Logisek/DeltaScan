from marshmallow import Schema, fields, pre_load, post_load


class UiContext(Schema):  # TODOL remove this schema or properly implement it
    progress = fields.Str(allow_none=True)


class ConfigSchema(Schema):
    is_interactive = fields.Bool(allow_none=True)
    output_file = fields.Str(allow_none=True)
    single = fields.Bool(allow_none=True)
    template_file = fields.Str(allow_none=True)
    import_file = fields.Str(allow_none=True)
    action = fields.Str(required=True)
    profile = fields.Str(allow_none=True)
    conf_file = fields.Str(allow_none=True)
    verbose = fields.Bool(allow_none=True)
    suppress = fields.Bool(allow_none=True)
    n_scans = fields.Int(allow_none=True)
    n_diffs = fields.Int(allow_none=True)
    fdate = fields.Str(allow_none=True)
    tdate = fields.Str(allow_none=True)
    port_type = fields.Str(allow_none=True)
    host = fields.Str(allow_none=True)


class ScanPorts(Schema):
    portid = fields.Str(required=True)
    proto = fields.Str(required=True)
    state = fields.Dict(required=True)
    service = fields.Str(required=True)
    servicefp = fields.Str(required=True)
    service_product = fields.Str(required=True)


class Scan(Schema):
    host = fields.Str(required=True)
    status = fields.Str(required=True)
    ports = fields.Nested(ScanPorts, many=True, required=True)
    os = fields.List(fields.Str(), required=True)
    hops = fields.Raw(required=True)
    osfingerprint = fields.Str(required=True)
    last_boot = fields.Str(required=True)


class DBScan(Schema):  # TODO: rename DBScan to ScanFromDB
    id = fields.Int(required=True)
    uuid = fields.Str(required=True)
    host = fields.Str(required=True)
    profile_name = fields.Str(required=True)
    arguments = fields.Str(required=True)
    results = fields.Nested(Scan, required=True)
    result_hash = fields.Str(required=True)
    created_at = fields.Str(required=True)

    @pre_load
    def pre_load(self, data, **kwargs):
        if isinstance(data, dict) and "created_at" in data:
            data["created_at"] = str(data["created_at"])
        return data


class ReportScanFromDB(Schema):
    id = fields.Int(required=True)
    uuid = fields.Str(required=True)
    host = fields.Str(required=True)
    profile_name = fields.Str(required=True)
    arguments = fields.Str(required=True)
    results = fields.Nested(Scan, required=True)
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
    diffs = fields.Dict(fields.Raw(), required=True)
    generic = fields.Dict(fields.Str(), required=True)
    uuids = fields.List(fields.Str(), required=True)


class Diffs(Schema):
    ids = fields.List(fields.Int(), required=True)
    uuids = fields.List(fields.Str(), required=True)
    dates = fields.List(fields.Str(), required=True)
    generic = fields.Dict(fields.Str(), required=True)
    diffs = fields.Dict(required=True)
    result_hashes = fields.List(fields.Str(), required=True)
