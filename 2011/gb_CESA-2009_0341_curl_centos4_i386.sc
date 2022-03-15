if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-April/015808.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880917" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2009:0341" );
	script_cve_id( "CVE-2009-0037" );
	script_name( "CentOS Update for curl CESA-2009:0341 centos4 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "curl on CentOS 4" );
	script_tag( name: "insight", value: "cURL is a tool for getting files from FTP, HTTP, Gopher, Telnet, and Dict
  servers, using any of the supported protocols. cURL is designed to work
  without user interaction or any kind of interactivity.

  David Kierznowski discovered a flaw in libcurl where it would not
  differentiate between different target URLs when handling automatic
  redirects. This caused libcurl to follow any new URL that it understood,
  including the 'file://' URL type. This could allow a remote server to force
  a local libcurl-using application to read a local file instead of the
  remote one, possibly exposing local files that were not meant to be
  exposed. (CVE-2009-0037)

  Note: Applications using libcurl that are expected to follow redirects to
  'file://' protocol must now explicitly call curl_easy_setopt(3) and set the
  newly introduced CURLOPT_REDIR_PROTOCOLS option as required.

  cURL users should upgrade to these updated packages, which contain
  backported patches to correct these issues. All running applications using
  libcurl must be restarted for the update to take effect." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS4"){
	if(( res = isrpmvuln( pkg: "curl", rpm: "curl~7.12.1~11.1.el4_7.1", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "curl-devel", rpm: "curl-devel~7.12.1~11.1.el4_7.1", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

