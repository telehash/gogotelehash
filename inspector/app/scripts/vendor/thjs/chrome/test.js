window.onload = load;

function load()
{
  console.log("loaded");
  thforge.forge(forge);
  thjs.debug(function(){console.log.apply(console,arguments)});
  getId(function(id){
    udp.create(function(sock){
      if(!sock) return;
      console.log(sock,id);
    	me = thjs.hashname(id, function(to, msg) {
        console.log("sending", to.hashname, msg.length());
        sock.send(to, msg.bytes());
      });
      // every 10 sec update local IP
      function locals(){
        sock.setLocal(me);
        setTimeout(locals, 10000);
      }
      sock.receive = function(msg,from){me.receive(msg,from)};
    	console.log("switch created",me);
      document.querySelector("#hashname").innerHTML = me.hashname;
			id.seeds.forEach(me.addSeed, me);
      sock.setLocal(me, function(){
        setTimeout(locals, 10000); // start monitoring
  			me.online(function(err,to){
  			  console.log("online",err,to&&to.hashname);
          document.querySelector("#online").innerHTML = err||"online";
        });        
      });
    });
  });
}

function seeds(id, callback)
{
  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function() {
    if(!id || !xhr.responseText) return;
    id.seeds = JSON.parse(xhr.responseText);
    callback(id);
    id = false;
  }
  xhr.open("GET", "seeds.json", true);
  xhr.send();
  
}

function getId(callback)
{
	chrome.storage.local.get(["public","private"], function(id){
	  if(id.public) return seeds(id, callback);
    thforge.genkey(function(err, id){
      chrome.storage.local.set(id);
      seeds(id, callback);
    });
	});
}