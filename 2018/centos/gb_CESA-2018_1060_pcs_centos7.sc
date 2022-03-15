if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882895" );
	script_version( "2021-05-21T08:11:46+0000" );
	script_tag( name: "last_modification", value: "2021-05-21 08:11:46 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2018-06-05 14:03:24 +0530 (Tue, 05 Jun 2018)" );
	script_cve_id( "CVE-2018-1079", "CVE-2018-1086", "CVE-2018-1000119" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:38:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for pcs CESA-2018:1060 centos7" );
	script_tag( name: "summary", value: "Check the version of pcs" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The pcs packages provide a command-line configuration system for the
Pacemaker and Corosync utilities.

Security Fix(es):

  * pcs: Privilege escalation via authorized user malicious REST call
(CVE-2018-1079)

  * pcs: Debug parameter removal bypass, allowing information disclosure
(CVE-2018-1086)

  * rack-protection: Timing attack in authenticity_token.rb
(CVE-2018-1000119)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

The CVE-2018-1079 issue was discovered by Ondrej Mular (Red Hat) and the
CVE-2018-1086 issue was discovered by Cedric Buissart (Red Hat)." );
	script_tag( name: "affected", value: "pcs on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2018:1060" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-May/022893.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "pcs", rpm: "pcs~0.9.162~5.el7.centos.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pcs-snmp", rpm: "pcs-snmp~0.9.162~5.el7.centos.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

