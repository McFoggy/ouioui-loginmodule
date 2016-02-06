# OuiOuiLoginModule [![Build Status](https://travis-ci.org/McFoggy/ouioui-loginmodule.svg?branch=master)](https://travis-ci.org/McFoggy/ouioui-loginmodule)

The 'Noddy' login module is a no deps JAAS compliant LoginModule mainly focused for tests, load tests or integration scenarios.

## Goals

The LoginModule has been created to:

- authenticate any incoming call that has at least a name (password is not mandatory)
- fill standard _tryFirstPass_ shared state entries: `javax.security.auth.login.name` & `javax.security.auth.login.password`, so that it can integrates smoothly on top of standard JAAS security domain definition
- support basic role assignment

## Options

The LoginModule has very few available options (is one very few ? ;-) )

- `roles`: a comma separated list of role names that will be assigned to the authenticated principal during authorization phase

## Use cases

- __user is not that important__: if your application does not store/use data from the user but relies on their login/role only then ouioui-loginmodule is a perfect tool to load test it. 
- __users are meaningful but you don't know their login__: in such cases you can benefit from the ouioui-loginmodule ability to authenticate automatically your calls and then delegate to the rest of the JAAS stack (using _tryFirstPass_) to fill-in expected roles & principals.

## Wildfly integration

The project produce a ready to use wildfly module.

- Unzip `ouioui-loginmodule-XXX-wildfly-module.zip` into `WILDFLY_HOME\modules`
- Update the wildfly configuration

```
<security-domain name="????" cache-type="default">
	...
    <authentication>
        <login-module code="fr.brouillard.oss.security.jaas.OuiOuiLoginModule" flag="required" module="fr.brouillard.oss.security.jaas">
            <module-option name="roles" value="USER,ADMIN"/>
        </login-module>
    </authentication>
    ...
</security-domain>
```

et voilà !
