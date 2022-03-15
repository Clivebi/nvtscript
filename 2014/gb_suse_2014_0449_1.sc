if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850579" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2014-04-03 12:52:28 +0530 (Thu, 03 Apr 2014)" );
	script_cve_id( "CVE-2014-2323", "CVE-2014-2324" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "openSUSE: Security Advisory for lighttpd (openSUSE-SU-2014:0449-1)" );
	script_tag( name: "affected", value: "lighttpd on openSUSE 13.1, openSUSE 12.3" );
	script_tag( name: "insight", value: "lighttpd was updated to version 1.4.35, fixing bugs and
  security issues:

  CVE-2014-2323: SQL injection vulnerability in
  mod_mysql_vhost.c in lighttpd allowed remote attackers to
  execute arbitrary SQL commands via the host name, related
  to request_check_hostname.

  CVE-2014-2323: Multiple directory traversal vulnerabilities
  in (1) mod_evhost and (2) mod_simple_vhost in lighttpd
  allowed remote attackers to read arbitrary files via a ..
  (dot dot) in the host name, related to
  request_check_hostname.

  More information can be found on the referenced lighttpd advisory page.

  Other changes:

  * [network/ssl] fix build error if TLSEXT is disabled

  * [mod_fastcgi] fix use after free (only triggered if
  fastcgi debug is active)

  * [mod_rrdtool] fix invalid read (string not null
  terminated)

  * [mod_dirlisting] fix memory leak if pcre fails

  * [mod_fastcgi, mod_scgi] fix resource leaks on spawning
  backends

  * [mod_magnet] fix memory leak

  * add comments for switch fall throughs

  * remove logical dead code

  * [buffer] fix length check in buffer_is_equal_right_len

  * fix resource leaks in error cases on config parsing and
  other initializations

  * add force_assert() to enforce assertions as simple
  assert()s are disabled by -DNDEBUG (fixes #2546)

  * [mod_cml_lua] fix null pointer dereference

  * force assertion: setting FD_CLOEXEC must work (if
  available)

  * [network] check return value of lseek()

  * fix unchecked return values from
  stream_open/stat_cache_get_entry

  * [mod_webdav] fix logic error in handling file creation
  error

  * check length of unix domain socket filenames

  * fix SQL injection / host name validation (thx Jann Horn)
  for all the changes see
  /usr/share/doc/packages/lighttpd/NEWS" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "openSUSE-SU", value: "2014:0449-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lighttpd'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSE12\\.3|openSUSE13\\.1)" );
	script_xref( name: "URL", value: "http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2014_01.txt" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "openSUSE12.3"){
	if(!isnull( res = isrpmvuln( pkg: "lighttpd", rpm: "lighttpd~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-debuginfo", rpm: "lighttpd-debuginfo~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-debugsource", rpm: "lighttpd-debugsource~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_cml", rpm: "lighttpd-mod_cml~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_cml-debuginfo", rpm: "lighttpd-mod_cml-debuginfo~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_geoip", rpm: "lighttpd-mod_geoip~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_geoip-debuginfo", rpm: "lighttpd-mod_geoip-debuginfo~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_magnet", rpm: "lighttpd-mod_magnet~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_magnet-debuginfo", rpm: "lighttpd-mod_magnet-debuginfo~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_mysql_vhost", rpm: "lighttpd-mod_mysql_vhost~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_mysql_vhost-debuginfo", rpm: "lighttpd-mod_mysql_vhost-debuginfo~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_rrdtool", rpm: "lighttpd-mod_rrdtool~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_rrdtool-debuginfo", rpm: "lighttpd-mod_rrdtool-debuginfo~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_trigger_b4_dl", rpm: "lighttpd-mod_trigger_b4_dl~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_trigger_b4_dl-debuginfo", rpm: "lighttpd-mod_trigger_b4_dl-debuginfo~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_webdav", rpm: "lighttpd-mod_webdav~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_webdav-debuginfo", rpm: "lighttpd-mod_webdav-debuginfo~1.4.35~6.9.1", rls: "openSUSE12.3" ) )){
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
}
if(release == "openSUSE13.1"){
	if(!isnull( res = isrpmvuln( pkg: "lighttpd", rpm: "lighttpd~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-debuginfo", rpm: "lighttpd-debuginfo~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-debugsource", rpm: "lighttpd-debugsource~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_cml", rpm: "lighttpd-mod_cml~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_cml-debuginfo", rpm: "lighttpd-mod_cml-debuginfo~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_geoip", rpm: "lighttpd-mod_geoip~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_geoip-debuginfo", rpm: "lighttpd-mod_geoip-debuginfo~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_magnet", rpm: "lighttpd-mod_magnet~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_magnet-debuginfo", rpm: "lighttpd-mod_magnet-debuginfo~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_mysql_vhost", rpm: "lighttpd-mod_mysql_vhost~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_mysql_vhost-debuginfo", rpm: "lighttpd-mod_mysql_vhost-debuginfo~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_rrdtool", rpm: "lighttpd-mod_rrdtool~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_rrdtool-debuginfo", rpm: "lighttpd-mod_rrdtool-debuginfo~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_trigger_b4_dl", rpm: "lighttpd-mod_trigger_b4_dl~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_trigger_b4_dl-debuginfo", rpm: "lighttpd-mod_trigger_b4_dl-debuginfo~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_webdav", rpm: "lighttpd-mod_webdav~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lighttpd-mod_webdav-debuginfo", rpm: "lighttpd-mod_webdav-debuginfo~1.4.35~2.9.1", rls: "openSUSE13.1" ) )){
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
}
exit( 0 );

