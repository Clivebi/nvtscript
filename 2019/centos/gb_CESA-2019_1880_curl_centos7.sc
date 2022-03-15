if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883093" );
	script_version( "2021-08-27T13:01:16+0000" );
	script_cve_id( "CVE-2018-14618" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-27 13:01:16 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-22 17:48:00 +0000 (Mon, 22 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-08-01 02:01:03 +0000 (Thu, 01 Aug 2019)" );
	script_name( "CentOS Update for curl CESA-2019:1880 centos7 " );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2019:1880" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2019-July/023377.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl'
  package(s) announced via the CESA-2019:1880 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The curl packages provide the libcurl library and the curl utility for
downloading files from servers using various protocols, including HTTP,
FTP, and LDAP.

Security Fix(es):

  * curl: NTLM password overflow via integer overflow (CVE-2018-14618)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * baseurl with file:// hangs and then timeout in yum repo (BZ#1709474)

  * curl crashes on http links with rate-limit (BZ#1711914)" );
	script_tag( name: "affected", value: "'curl' package(s) on CentOS 7." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "curl", rpm: "curl~7.29.0~51.el7_6.3", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl", rpm: "libcurl~7.29.0~51.el7_6.3", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl-devel", rpm: "libcurl-devel~7.29.0~51.el7_6.3", rls: "CentOS7" ) )){
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

