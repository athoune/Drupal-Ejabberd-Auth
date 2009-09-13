-- SUMMARY --

Drupal module to use drupal database for ejabberd authentification

Initial work from http://yo.jabber.ru/bugzilla/show_bug.cgi?id=385

-- REQUIREMENTS --

Ejabberd from http://www.ejabberd.im/. Yes, it's a drupal website.

It should be packaged in your linux distribution.

-- USAGE --

In ejabberd.cfg, choose the right authentification method

8<------------------------------------------------------

{auth_method, external}.
{extauth_program, "/path/to/ejabberd_auth.phps"}.

------------------------------------------------------>8

Only Jabber handle new user :

8<------------------------------------------------------

% None username can be registered via in-band registration:
{access, register, [{deny, all}]}.

------------------------------------------------------>8

The script is generated when you save the settings in the drupal admin page.

-- CONTACT --
Mathieu - http://drupal.org/user/378820
