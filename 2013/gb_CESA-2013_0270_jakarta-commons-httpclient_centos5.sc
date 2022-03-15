if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-February/019241.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881604" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-02-22 10:04:51 +0530 (Fri, 22 Feb 2013)" );
	script_cve_id( "CVE-2012-5783" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_xref( name: "CESA", value: "2013:0270" );
	script_name( "CentOS Update for jakarta-commons-httpclient CESA-2013:0270 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jakarta-commons-httpclient'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "jakarta-commons-httpclient on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The Jakarta Commons HttpClient component can be used to build HTTP-aware
  client applications (such as web browsers and web service clients).

  The Jakarta Commons HttpClient component did not verify that the server
  hostname matched the domain name in the subject's Common Name (CN) or
  subjectAltName field in X.509 certificates. This could allow a
  man-in-the-middle attacker to spoof an SSL server if they had a certificate
  that was valid for any domain name. (CVE-2012-5783)

  All users of jakarta-commons-httpclient are advised to upgrade to these
  updated packages, which correct this issue. Applications using the Jakarta
  Commons HttpClient component must be restarted for this update to take
  effect." );
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
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "jakarta-commons-httpclient", rpm: "jakarta-commons-httpclient~3.0~7jpp.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "jakarta-commons-httpclient-demo", rpm: "jakarta-commons-httpclient-demo~3.0~7jpp.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "jakarta-commons-httpclient-javadoc", rpm: "jakarta-commons-httpclient-javadoc~3.0~7jpp.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "jakarta-commons-httpclient-manual", rpm: "jakarta-commons-httpclient-manual~3.0~7jpp.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

