var udp = {};

var ab2str=function(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
};
var str2ab=function(str) {
  var buf=new ArrayBuffer(str.length);
  var bufView=new Uint8Array(buf);
  for (var i=0; i<str.length; i++) {
    bufView[i]=str.charCodeAt(i);
  }
  return buf;
}

function poll(id)
{
  var sock = this;
  chrome.socket.recvFrom(id, 1500, function(msg){
    console.log("message",msg);
    if (msg.resultCode >= 0) {
      console.log("udp recv",msg.address,msg.port,msg.data.byteLength);
      var type = msg.address.indexOf(":")?"ipv6":"ipv4"
      if(sock.receive) sock.receive(ab2str(msg.data),{type:type,ip:msg.address,port:msg.port,id:msg.address+msg.port});
      sock.poll(id);
    } else {
      //poof
    }
  });
}

function sock(address, callback)
{
  chrome.socket.create("udp", function(sock){
    chrome.socket.bind(sock.socketId, address, 0, function(err){
      if(err) return chrome.socket.destroy(sock.socketId) + callback();
      chrome.socket.getInfo(sock.socketId, function(info){
        console.log("socket info",address,info);
        info.id = sock.socketId;
        callback(info);
      });
    });
  }); 
}

udp.create = function(cb)
{
  // it seems like chrome might support one socket for both, but in some limited testing it wasn't working
  // needs to be sorely refactored too, it's just a starting point

  // make the ipv4 and ipv6 sockets
  sock("0.0.0.0",function(sock4){
    sock("::0",function(sock6){
      var sock = {};
      sock.sock4 = sock4;
      sock.sock6 = sock6;
      sock.poll = poll;
      sock.poll(sock4.id);
      sock.poll(sock6.id);
      sock.send = function(to, msg){
        if(to.type != "ipv4" && to.type != "ipv6") return;
        console.log("udp send",to.ip,to.port,msg.length);
        var id = (to.type == "ipv4") ? sock4.id : sock6.id;
        chrome.socket.sendTo(id, str2ab(msg), to.ip, parseInt(to.port), function(wi){
          console.log("sendTo",wi);
        });
      }
      // update the .ip and .port to local addresses, TODO, refactor this, feels out of place
      sock.setLocal = function(obj, done){
        // get the current ipv4 address from the local network interfaces
        chrome.socket.getNetworkList(function(local){
          console.log("LOCAL",local);
          var ip4, ip6;
          if(Array.isArray(local)) local.forEach(function(iface){
            if(iface.address && iface.address.split(".").length == 4) ip4 = iface.address;
            if(iface.address && iface.address.split(":").length > 1) ip6 = iface.address;
          });
          if(ip4) obj.pathSet({type:"ipv4",ip:ip4,port:sock.localPort});
          if(ip6) obj.pathSet({type:"ipv6",ip:ip6,port:sock.localPort});
          if(done) done();
        });          
      }
      cb(sock);
    })
  })
}

