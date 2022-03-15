if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883199" );
	script_version( "2021-07-06T02:00:40+0000" );
	script_cve_id( "CVE-2019-18634" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-07 17:15:00 +0000 (Fri, 07 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-03-11 04:00:40 +0000 (Wed, 11 Mar 2020)" );
	script_name( "CentOS: Security Advisory for sudo (CESA-2020:0726)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2020:0726" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-March/035656.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sudo'
  package(s) announced via the CESA-2020:0726 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The sudo packages contain the sudo utility which allows system
administrators to provide certain users with the permission to execute
privileged commands, which are used for system management purposes, without
having to log in as root.

Security Fix(es):

  * sudo: Stack based buffer overflow when pwfeedback is enabled
(CVE-2019-18634)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'sudo' package(s) on CentOS 6." );
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
if(release == "CentOS6"){
	if(!isnull( res = isrpmvuln( pkg: "sudo", rpm: "sudo~1.8.6p3~29.el6_10.3", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sudo-devel", rpm: "sudo-devel~1.8.6p3~29.el6_10.3", rls: "CentOS6" ) )){
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

