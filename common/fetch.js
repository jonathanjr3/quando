function _fetch(method, url, success, fail = false, send_data = false, file_upload = false) {
    console.log('Fetch Debug:', {
        method,
        url,
        hostname: window.location.hostname,
        origin: window.location.origin,
        send_data: !!send_data,
        file_upload
    });

    let params = { method: method }
    if (!file_upload) {
        // only set content type when not a file upload...
        params['headers'] = {"Content-Type": "text/plain"}
    }
    
    // For mobile devices accessing over network, don't use no-cors mode
    // as it prevents reading the response body
    const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    console.log('Is localhost:', isLocalhost);
    
    if (!['DELETE', 'PUT'].includes(method) && isLocalhost) {
        // Only use no-cors mode for localhost access
        params['mode'] = "no-cors"
        console.log('Using no-cors mode for localhost');
    } else {
        // For remote access, use cors mode with credentials
        params['mode'] = "cors"
        params['credentials'] = "include"
        console.log('Using cors mode for remote access');
    }
    
    if (send_data) {
        if (file_upload) {
            params['body'] = send_data
        } else {
            params['body'] = JSON.stringify(send_data)
        }
    }
    
    console.log('Fetch params:', params);
    
    fetch(url, params).then((response) => {
        console.log('Response received:', {
            status: response.status,
            statusText: response.statusText,
            mode: params['mode'],
            ok: response.ok
        });
        
        // For no-cors mode, we can't read the response body
        if (params['mode'] === 'no-cors') {
            // Assume success for no-cors mode
            console.log('No-cors mode: assuming success');
            success({ success: true })
            return
        }
        return response.json()
    }).then((res) => {
        console.log('Parsed response:', res);
        if (res && res.success) {
            success(res)
        } else {
            console.log('Response indicates failure:', res);
            if (fail) { fail(res) }
        }
    }).catch((err) => {
        console.error('Fetch error details:', {
            error: err,
            message: err.message,
            stack: err.stack,
            type: err.name,
            hostname: window.location.hostname,
            mode: params['mode']
        });
        
        const errorMessage = isLocalhost ? 'Failed to find Quando:Local' : 'Network connection failed - check server is running'
        alert(errorMessage + '\nCheck browser console for details.')
        console.log(err)
    })
}

export function Get(url, success, fail, send_data = false) {
    _fetch("GET", url, success, fail, send_data)
}

export function Post(url, success, fail, send_data = false) {
    _fetch("POST", url, success, fail, send_data)
}

export function Post_file(url, success, fail, send_data) {
    _fetch("POST", url, success, fail, send_data, true)
}

export function Delete(url, success, fail, send_data = false) {
    _fetch("DELETE", url, success, fail, send_data)
}

export function Put(url, success, fail, send_data = false) {
    _fetch("PUT", url, success, fail, send_data)
}