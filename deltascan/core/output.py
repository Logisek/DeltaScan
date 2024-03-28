class Output:
    data: list[dict]

    @staticmethod
    def _construct_exported_diff_data(row, field_names):
        """
        Constructs and returns a list of exported diff data based on the given row and field names.

        Args:
            row (dict): The row containing the diff data.
            field_names (list): The list of field names.

        Returns:
            list: A list of exported diff data.

        """
        exported_diffs = []
        for _k in row["diffs"]["changed"]:
            _t = {
                "date_from": row["date_from"],
                "date_to": row["date_to"],
            }
            _t["from"] = _k[-3]
            _t["to"] = _k[-1]
            c = 0
            for _hf in field_names[2:-2]:
                try:
                    _t[_hf] = "" if (_k[c] == "from" or _k[c] == "to") or (_k[c] == _k[-3] or _k[c] == _k[-1]) else _k[c]
                    c += 1
                except IndexError:
                    break
            r = _t
            for _f in field_names:
                if _f not in r:
                    r[_f] = ""
            exported_diffs.append(r)
        return exported_diffs

    def _field_names_for_diff_results(self):
        """
        Returns a list of field names for the diff results.

        The field names include 'date_from', 'date_to', and dynamically generated field names
        based on the number of differences in the data.

        Returns:
            list: A list of field names.
        """
        max_length = 0
        for _d in self.data:
            if max(len(row) for row in _d["diffs"]) > max_length:
                max_length = max(len(row) for row in _d["diffs"])
        # We have to be careful of the logic here
        # The first 2 elements are the dates
        # The last 2 are the from and to fields
        # All the rest in the middle are the fields that their count depends on the nests layers of the 
        # diffs dictionary. the max-length-2 is the diffs length minus 2 (to and from)
        return list(["date_from", "date_to"] + ["field_" + str(i) for i in range(1, max_length-2)] + ["from", "to"])
