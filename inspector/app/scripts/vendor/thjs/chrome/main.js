chrome.app.runtime.onLaunched.addListener(function() {
  chrome.app.window.create('test.html', {
  	id: "mainwin",
    bounds: {
      width: 600,
      height: 800
    }
  });
});
