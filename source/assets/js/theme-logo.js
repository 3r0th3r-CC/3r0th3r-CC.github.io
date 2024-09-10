(function(win) {
  const setLogoForTheme = () => {
    const theme = document.documentElement.getAttribute('data-theme');
    const logo = document.getElementById('site-logo');
    if (logo) {
      if (theme === 'dark') {
        logo.src = logo.getAttribute('data-dark');
      } else {
        logo.src = logo.getAttribute('data-light');
      }
    }
  };

  win.addEventListener('DOMContentLoaded', setLogoForTheme);

  win.activateDarkMode = () => {
    document.documentElement.setAttribute('data-theme', 'dark');
    setLogoForTheme();
  };

  win.activateLightMode = () => {
    document.documentElement.setAttribute('data-theme', 'light');
    setLogoForTheme();
  };
})(window);
