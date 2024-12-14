vcl 4.1;

import std;

backend default {
    .host = "127.0.0.1";
    .port = "8080";
}

acl purge {
    "localhost";
    "127.0.0.1";
    "172.17.0.1";
}

sub vcl_recv {
    # Remove empty query strings like ? at the end
    if (req.url ~ "\?$") {
        set req.url = regsub(req.url, "\?$", "");
    }

    # Strip port from Host header
    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");

    # Sort query parameters to normalize the URL for caching
    set req.url = std.querysort(req.url);

    # Remove the proxy header (httpoxy vulnerability)
    unset req.http.proxy;

    # Set X-Forwarded-Proto based on server port
    if (!req.http.X-Forwarded-Proto) {
        if(std.port(server.ip) == 443 || std.port(server.ip) == 8443) {
            set req.http.X-Forwarded-Proto = "https";
        } else {
            set req.http.X-Forwarded-Proto = "http";
        }
    }

    # PURGE logic for the Proxy Cache Purge plugin
    if(req.method == "PURGE") {
        if(!client.ip ~ purge) {
            return(synth(405,"PURGE not allowed for this IP address"));
        }
        if (req.http.X-Purge-Method == "regex") {
            ban("obj.http.x-url ~ " + req.url + " && obj.http.x-host == " + req.http.host);
            return(synth(200, "Purged"));
        }
        ban("obj.http.x-url == " + req.url + " && obj.http.x-host == " + req.http.host);
        return(synth(200, "Purged"));
    }

    # Allow only specific HTTP methods to avoid issues
    if (
        req.method != "GET" &&
        req.method != "HEAD" &&
        req.method != "PUT" &&
        req.method != "POST" &&
        req.method != "PATCH" &&
        req.method != "TRACE" &&
        req.method != "OPTIONS" &&
        req.method != "DELETE"
    ) {
        return (pipe);
    }

    # Remove tracking parameters (utm_*, gclid, etc.)
    if (req.url ~ "(\?|&)(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=") {
        set req.url = regsuball(req.url, "&(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "");
        set req.url = regsuball(req.url, "\?(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "?");
        set req.url = regsub(req.url, "\?&", "?");
        set req.url = regsub(req.url, "\?$", "");
    }

    # Only cache GET and HEAD
    if (req.method != "GET" && req.method != "HEAD") {
        set req.http.X-Cacheable = "NO:REQUEST-METHOD";
        return(pass);
    }

    # Identify static files and remove cookies for them
    if (req.url ~ "^[^?]*\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|ogg|ogm|opus|otf|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\?.*)?$") {
        set req.http.X-Static-File = "true";
        unset req.http.Cookie;
    }

    # WordPress/WooCommerce dynamic pages and logged-in users: don't cache
    if (
        req.http.Cookie ~ "wordpress_(?!test_)[a-zA-Z0-9_]+|wp-postpass|comment_author_[a-zA-Z0-9_]+|woocommerce_cart_hash|woocommerce_items_in_cart|wp_woocommerce_session_[a-zA-Z0-9]+|wordpress_logged_in_|comment_author|PHPSESSID" ||
        req.http.Authorization ||
        req.url ~ "add_to_cart" ||
        req.url ~ "edd_action" ||
        req.url ~ "nocache" ||
        req.url ~ "^/addons" ||
        req.url ~ "^/bb-admin" ||
        req.url ~ "^/bb-login.php" ||
        req.url ~ "^/bb-reset-password.php" ||
        req.url ~ "^/cart" ||
        req.url ~ "^/checkout" ||
        req.url ~ "^/control.php" ||
        req.url ~ "^/login" ||
        req.url ~ "^/logout" ||
        req.url ~ "^/lost-password" ||
        req.url ~ "^/my-account" ||
        req.url ~ "^/product" ||
        req.url ~ "^/register" ||
        req.url ~ "^/register.php" ||
        req.url ~ "^/server-status" ||
        req.url ~ "^/signin" ||
        req.url ~ "^/signup" ||
        req.url ~ "^/stats" ||
        req.url ~ "^/wc-api" ||
        req.url ~ "^/wp-admin" ||
        req.url ~ "^/wp-comments-post.php" ||
        req.url ~ "^/wp-cron.php" ||
        req.url ~ "^/wp-login.php" ||
        req.url ~ "^/wp-activate.php" ||
        req.url ~ "^/wp-mail.php" ||
        req.url ~ "^\?add-to-cart=" ||
        req.url ~ "^\?wc-api=" ||
        req.url ~ "^/preview=" ||
        req.url ~ "^/\.well-known/acme-challenge/"
    ) {
        set req.http.X-Cacheable = "NO:Logged in/Got Sessions";
        if(req.http.X-Requested-With == "XMLHttpRequest") {
            set req.http.X-Cacheable = "NO:Ajax";
        }
        return(pass);
    }

    # Normalize and unify headers to prevent separate caching for Chrome/Safari
    if (req.http.Accept-Encoding) {
        if (req.http.Accept-Encoding ~ "br" || req.http.Accept-Encoding ~ "gzip") {
            set req.http.Accept-Encoding = "gzip";
        } else {
            unset req.http.Accept-Encoding;
        }
    }

    # Remove headers that vary by browser
    unset req.http.User-Agent;
    unset req.http.Accept;
    unset req.http.Accept-Language;
    unset req.http.Sec-Fetch-Mode;
    unset req.http.Sec-Fetch-Site;
    unset req.http.Sec-Fetch-User;
    unset req.http.Upgrade-Insecure-Requests;

    # Remove any remaining cookies
    unset req.http.Cookie;

    return(hash);
}

sub vcl_hash {
    if(req.http.X-Forwarded-Proto) {
        hash_data(req.http.X-Forwarded-Proto);
    }
}

sub vcl_backend_response {
    # Inject URL & Host for purge/banning
    set beresp.http.x-url = bereq.url;
    set beresp.http.x-host = bereq.http.host;

    # Default TTL if no Cache-Control
    if (!beresp.http.Cache-Control) {
        set beresp.ttl = 1h;
        set beresp.http.X-Cacheable = "YES:Forced";
    }

    # Longer TTL for static files
    if (bereq.http.X-Static-File == "true") {
        unset beresp.http.Set-Cookie;
        set beresp.http.X-Cacheable = "YES:Forced";
        set beresp.ttl = 1d;
    }

    # Remove Wordfence cookies
    if (beresp.http.Set-Cookie ~ "wfvt_|wordfence_verifiedHuman") {
        unset beresp.http.Set-Cookie;
    }

    if (beresp.http.Set-Cookie) {
        set beresp.http.X-Cacheable = "NO:Got Cookies";
    } elseif(beresp.http.Cache-Control ~ "private") {
        set beresp.http.X-Cacheable = "NO:Cache-Control=private";
    }

    # Remove Accept-Language from Vary to unify caching
    if (beresp.http.Vary) {
        set beresp.http.Vary = regsub(beresp.http.Vary, "(,?\s*Accept-Language\s*)", "");
        set beresp.http.Vary = regsub(beresp.http.Vary, "^,\s*|\s*,\s*$", "");
        if (beresp.http.Vary == "") {
            unset beresp.http.Vary;
        }
    }
}

sub vcl_deliver {
    # Add X-Cache-Age based on Age
    if (resp.http.Age) {
        set resp.http.X-Cache-Age = resp.http.Age;
        unset resp.http.Age;
    }

    # Indicate HIT or MISS
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }

    # Debug header
    if(req.http.X-Cacheable) {
        set resp.http.X-Cacheable = req.http.X-Cacheable;
    } elseif(obj.uncacheable) {
        if(!resp.http.X-Cacheable) {
            set resp.http.X-Cacheable = "NO:UNCACHEABLE";
        }
    } elseif(!resp.http.X-Cacheable) {
        set resp.http.X-Cacheable = "YES";
    }

    # Cleanup internal headers
    unset resp.http.x-url;
    unset resp.http.x-host;
}
