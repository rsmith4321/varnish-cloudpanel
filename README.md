# varnish-cloudpanel
Fix for Varnish Settings on Cloudpanel to unify cache between different browsers and cache warming plugins

The default /etc/varnish/default.vcl settings implemented by Cloudpanel create separate page caches for Safari, Chrome and Cache Warming plugins. This makes Cache Warming ineffective. This fixes issues with the headers to unify the cache. It also has some Wordpress and WooCommerce specific improvements.
