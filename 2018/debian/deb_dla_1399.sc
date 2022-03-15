if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891399" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2015-7519", "CVE-2018-12029" );
	script_name( "Debian LTS: Security Advisory for ruby-passenger (DLA-1399-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-10 00:00:00 +0200 (Tue, 10 Jul 2018)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-08 14:12:00 +0000 (Fri, 08 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/06/msg00007.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "ruby-passenger on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
4.0.53-1+deb8u1.

We recommend that you upgrade your ruby-passenger packages." );
	script_tag( name: "summary", value: "Two flaws were discovered in ruby-passenger for Ruby Rails and Rack
support that allowed attackers to spoof HTTP headers or exploit a race
condition which made privilege escalation under certain conditions
possible.

CVE-2015-7519
Remote attackers could spoof headers passed to applications by using
an underscore character instead of a dash character in an HTTP
header as demonstrated by an X_User header.

CVE-2018-12029
A vulnerability was discovered by the Pulse Security team. It was
exploitable only when running a non-standard
passenger_instance_registry_dir, via a race condition where after a
file was created, there was a window in which it could be replaced
with a symlink before it was chowned via the path and not the file
descriptor. If the symlink target was to a file which would be
executed by root such as root's crontab file, then privilege
escalation was possible. This is now mitigated by using fchown()." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-passenger", ver: "4.0.53-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-passenger", ver: "4.0.53-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby-passenger-doc", ver: "4.0.53-1+deb8u1", rls: "DEB8" ) )){
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

