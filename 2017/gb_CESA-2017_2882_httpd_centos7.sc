if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882784" );
	script_version( "2021-09-09T12:15:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 12:15:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-12 10:25:42 +0200 (Thu, 12 Oct 2017)" );
	script_cve_id( "CVE-2017-9798" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for httpd CESA-2017:2882 centos7" );
	script_tag( name: "summary", value: "Check the version of httpd" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The httpd packages provide the Apache
HTTP Server, a powerful, efficient, and extensible web server.

Security Fix(es):

  * A use-after-free flaw was found in the way httpd handled invalid and
previously unregistered HTTP methods specified in the Limit directive used
in an .htaccess file. A remote attacker could possibly use this flaw to
disclose portions of the server memory, or cause httpd child process to
crash. (CVE-2017-9798)

Red Hat would like to thank Hanno Bock for reporting this issue." );
	script_tag( name: "affected", value: "httpd on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:2882" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-October/022565.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "httpd", rpm: "httpd~2.4.6~67.el7.centos.5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "httpd-devel", rpm: "httpd-devel~2.4.6~67.el7.centos.5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "httpd-manual", rpm: "httpd-manual~2.4.6~67.el7.centos.5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "httpd-tools", rpm: "httpd-tools~2.4.6~67.el7.centos.5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mod_ldap", rpm: "mod_ldap~2.4.6~67.el7.centos.5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mod_proxy_html", rpm: "mod_proxy_html~2.4.6~67.el7.centos.5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mod_session", rpm: "mod_session~2.4.6~67.el7.centos.5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mod_ssl", rpm: "mod_ssl~2.4.6~67.el7.centos.5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

