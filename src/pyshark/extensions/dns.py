from pyshark.extensions.base import LayerExtension


class DNSExtension(LayerExtension):
    PROTOCOL = "DNS"
    FOR_JSON = True

    @classmethod
    def get_queries(cls, dns_layer):
        from pyshark.packet.layer import JsonLayer
        queries = dns_layer.get_field("Queries", as_dict=True)

        # The key is currently the description
        for query_desc in queries:
            queries[query_desc]["description"] = query_desc
        return [JsonLayer("QUERY", query, full_name="dns") for query in queries.values()]


class MDNSExtension(DNSExtension):
    PROTOCOL = "mDNS"
