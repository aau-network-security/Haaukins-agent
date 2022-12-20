const params = new Proxy(new URLSearchParams(window.location.search), {
    get: (searchParams, prop) => searchParams.get(prop),
});

let username = params.username
let password = params.password
let vid = params.vid

let payload = new URLSearchParams({
    'username': username,
    'password': password
})

console.log(payload, JSON.stringify(payload));

fetch("/guacamole/api/tokens" , {
    method: 'POST',
    headers:{
        'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: payload
}).then(function(res){ 
    if (!res.ok) {
        document.write("Error when trying to login to Apache Guacamole");
        throw new Error("HTTP status " + res.status);
    }
    return res.json(); })
.then(function(data){ 
    localStorage.setItem('GUAC_AUTH', JSON.stringify(data));
    localStorage.removeItem('GUAC_HISTORY');
    localStorage.removeItem('GUAC_PREFERENCES')
    console.log("Sending to vm with id: " + vid);
    window.location.replace("/guacamole/#/client/" + vid);
})