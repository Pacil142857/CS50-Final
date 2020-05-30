// It works
// Don't touch it

function setTheme(themeName)
{
    if (themeName === 'dark')
    {
        document.body.classList.add('dark');
        localStorage.setItem('theme', 'dark');
        console.log('Dark');
    }
    else
    {
        document.body.classList.remove('dark');
        localStorage.setItem('theme', 'light');
        console.log('Light');
    }
}

function toggleTheme()
{
    if (localStorage.getItem('theme') === 'dark')
    {
        setTheme('light');
    }
    else
    {
        setTheme('dark');
    }
}

(function ()
{
    if (localStorage.getItem('theme') === 'dark')
    {
        setTheme('dark');
    }
    else
    {
        setTheme('light');
    }
}) ();

// Sure hope this works
function validate(evt)
{
  var theEvent = evt || window.event;

  // Handle paste
  if (theEvent.type === 'paste')
  {
      key = event.clipboardData.getData('text/plain');
  } else
  {
  // Handle key press
      var key = theEvent.keyCode || theEvent.which;
      key = String.fromCharCode(key);
  }
  var regex = /[0-9]|\./;
  if( !regex.test(key) )
  {
    theEvent.returnValue = false;
    if(theEvent.preventDefault) theEvent.preventDefault();
  }
}