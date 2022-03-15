if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883207" );
	script_version( "2021-07-06T02:00:40+0000" );
	script_cve_id( "CVE-2018-18074", "CVE-2018-20060", "CVE-2019-11236", "CVE-2019-11324" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 20:30:00 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-03-26 04:01:07 +0000 (Thu, 26 Mar 2020)" );
	script_name( "CentOS: Security Advisory for python3-pip (CESA-2020:0850)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2020:0850" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-March/035663.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python3-pip'
  package(s) announced via the CESA-2020:0850 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "TODO: add package description

Security Fix(es):

  * python-urllib3: Cross-host redirect does not remove Authorization header
allow for credential exposure (CVE-2018-20060)

  * python-urllib3: CRLF injection due to not encoding the '\\r\\n' sequence
leading to possible attack on internal service (CVE-2019-11236)

  * python-urllib3: Certification mishandle when error should be thrown
(CVE-2019-11324)

  * python-requests: Redirect from HTTPS to HTTP does not remove
Authorization header (CVE-2018-18074)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'python3-pip' package(s) on CentOS 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "python3-pip", rpm: "python3-pip~9.0.3~7.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-pip", rpm: "python-pip~9.0.3~7.el7_7", rls: "CentOS7" ) )){
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

