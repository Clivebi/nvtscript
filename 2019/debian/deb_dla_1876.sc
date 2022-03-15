if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891876" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-11187" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-08-12 02:00:10 +0000 (Mon, 12 Aug 2019)" );
	script_name( "Debian LTS: Security Advisory for gosa (DLA-1876-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/08/msg00009.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1876-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gosa'
  package(s) announced via the DLA-1876-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In GOsa?, an LDAP web-frontend written in PHP, a vulnerability was found
that could theoretically have lead to unauthorized access to the LDAP
database managed with FusionDirectory. LDAP queries' result status
('Success') checks had not been strict enough. The resulting output
containing the word 'Success' anywhere in the returned data during login
connection attempts would have returned 'LDAP success' to FusionDirectory
and possibly grant unwanted access." );
	script_tag( name: "affected", value: "'gosa' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.7.4+reloaded2-1+deb8u4.

We recommend that you upgrade your gosa packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gosa", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-desktop", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-dev", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-help-de", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-help-en", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-help-fr", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-help-nl", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-connectivity", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-dhcp", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-dhcp-schema", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-dns", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-dns-schema", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-fai", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-fai-schema", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-gofax", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-gofon", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-goto", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-kolab", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-kolab-schema", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-ldapmanager", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-mail", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-mit-krb5", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-mit-krb5-schema", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-nagios", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-nagios-schema", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-netatalk", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-opengroupware", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-openxchange", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-openxchange-schema", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-opsi", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-phpgw", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-phpgw-schema", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-phpscheduleit", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-phpscheduleit-schema", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-pptp", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-pptp-schema", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-pureftpd", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-pureftpd-schema", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-rolemanagement", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-rsyslog", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-samba", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-scalix", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-squid", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-ssh", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-ssh-schema", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-sudo", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-sudo-schema", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-systems", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-uw-imap", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-plugin-webdav", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gosa-schema", ver: "2.7.4+reloaded2-1+deb8u4", rls: "DEB8" ) )){
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

