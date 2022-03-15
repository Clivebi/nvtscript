if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891905" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-14466" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-10 19:28:00 +0000 (Fri, 10 Jan 2020)" );
	script_tag( name: "creation_date", value: "2019-09-01 02:00:08 +0000 (Sun, 01 Sep 2019)" );
	script_name( "Debian LTS: Security Advisory for gosa (DLA-1905-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/08/msg00039.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1905-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gosa'
  package(s) announced via the DLA-1905-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "GOsa? used unserialize to restore filter settings from a cookie. Since
this cookie was supplied by the client, authenticated users could have
passed arbitrary content to unserialized, which opened GOsa? up to a
potential PHP object injection." );
	script_tag( name: "affected", value: "'gosa' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.7.4+reloaded2-1+deb8u5.

We recommend that you upgrade your gosa packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gosa", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-desktop", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-dev", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-help-de", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-help-en", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-help-fr", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-help-nl", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-connectivity", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-dhcp", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-dhcp-schema", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-dns", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-dns-schema", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-fai", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-fai-schema", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-gofax", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-gofon", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-goto", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-kolab", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-kolab-schema", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-ldapmanager", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-mail", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-mit-krb5", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-mit-krb5-schema", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-nagios", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-nagios-schema", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-netatalk", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-opengroupware", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-openxchange", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-openxchange-schema", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-opsi", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-phpgw", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-phpgw-schema", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-phpscheduleit", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-phpscheduleit-schema", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-pptp", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-pptp-schema", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-pureftpd", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-pureftpd-schema", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-rolemanagement", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-rsyslog", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-samba", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-scalix", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-squid", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-ssh", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-ssh-schema", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-sudo", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-sudo-schema", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-systems", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-uw-imap", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-webdav", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-schema", ver: "2.7.4+reloaded2-1+deb8u5", rls: "DEB8" ) )){
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
exit( 0 );

