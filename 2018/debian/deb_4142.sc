if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704142" );
	script_version( "2021-06-21T03:34:17+0000" );
	script_cve_id( "CVE-2018-6758", "CVE-2018-7490" );
	script_name( "Debian Security Advisory DSA 4142-1 (uwsgi - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-17 00:00:00 +0100 (Sat, 17 Mar 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4142.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "uwsgi on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 2.0.7-1+deb8u2. This update additionally includes the fix for
CVE-2018-6758
which was aimed to be addressed in the upcoming jessie
point release.

For the stable distribution (stretch), this problem has been fixed in
version 2.0.14+20161117-3+deb9u2.

We recommend that you upgrade your uwsgi packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/uwsgi" );
	script_tag( name: "summary", value: "Marios Nicolaides discovered that the PHP plugin in uWSGI, a fast,
self-healing application container server, does not properly handle a
DOCUMENT_ROOT check during use of the --php-docroot option, allowing a
remote attacker to mount a directory traversal attack and gain
unauthorized read access to sensitive files located outside of the web
root directory." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-proxy-uwsgi", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-proxy-uwsgi-dbg", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-ruwsgi", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-ruwsgi-dbg", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-uwsgi", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-uwsgi-dbg", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-uwsgidecorators", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-uwsgidecorators", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-app-integration-plugins", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-core", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-dbg", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-emperor", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-extra", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-infrastructure-plugins", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-alarm-curl", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-alarm-xmpp", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-curl-cron", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-emperor-pg", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-fiber", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-geoip", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-graylog2", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-greenlet-python", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-jvm-openjdk-7", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-jwsgi-openjdk-7", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-ldap", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-lua5.1", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-lua5.2", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-luajit", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-php", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-psgi", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-python", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-python3", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-rack-ruby2.1", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-rados", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-rbthreads", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-router-access", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-sqlite3", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-v8", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-xslt", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugins-all", ver: "2.0.7-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-proxy-uwsgi", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-proxy-uwsgi-dbg", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-ruwsgi", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-ruwsgi-dbg", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-uwsgi", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-uwsgi-dbg", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-uwsgidecorators", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-uwsgidecorators", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-app-integration-plugins", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-core", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-dbg", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-emperor", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-extra", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-infrastructure-plugins", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-mongodb-plugins", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-alarm-curl", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-alarm-xmpp", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-asyncio-python", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-asyncio-python3", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-curl-cron", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-emperor-pg", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-fiber", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-gccgo", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-geoip", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-gevent-python", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-glusterfs", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-graylog2", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-greenlet-python", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-jvm-openjdk-8", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-jwsgi-openjdk-8", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-ldap", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-lua5.1", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-lua5.2", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-luajit", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-mono", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-php", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-psgi", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-python", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-python3", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-rack-ruby2.3", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-rados", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-rbthreads", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-ring-openjdk-8", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-router-access", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-servlet-openjdk-8", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-sqlite3", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-tornado-python", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-v8", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugin-xslt", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-plugins-all", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uwsgi-src", ver: "2.0.14+20161117-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

