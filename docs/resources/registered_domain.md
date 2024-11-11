---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "banyan_registered_domain Resource - terraform-provider-banyan"
subcategory: ""
description: |-
  Registered domain resource allows for configuration of the registered domain API object
---

# banyan_registered_domain (Resource)

Registered domain resource allows for configuration of the registered domain API object



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `cluster` (String) cluster name used to identify if cluster type is private edge or global edge
- `cname` (String) CNAME of the access-tier
- `name` (String) Name of the registered domain

### Optional

- `description` (String) description of registered domain

### Read-Only

- `dns_setting` (List of Object) List of dns settings required for registered domain (see [below for nested schema](#nestedatt--dns_setting))
- `id` (String) Unique ID for a registered domain

<a id="nestedatt--dns_setting"></a>
### Nested Schema for `dns_setting`

Read-Only:

- `name` (String)
- `type` (String)
- `value` (String)