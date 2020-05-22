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