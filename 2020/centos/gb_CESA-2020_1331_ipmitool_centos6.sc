if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883218" );
	script_version( "2021-07-06T02:00:40+0000" );
	script_cve_id( "CVE-2020-5208" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-01 03:15:00 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-04-09 03:00:52 +0000 (Thu, 09 Apr 2020)" );
	script_name( "CentOS: Security Advisory for ipmitool (CESA-2020:1331)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2020:1331" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-April/035693.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ipmitool'
  package(s) announced via the CESA-2020:1331 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The ipmitool packages contain a command-line utility for interfacing with
devices that support the Intelligent Platform Management Interface (IPMI)
specification. IPMI is an open standard for machine health, inventory, and
remote power control.

Security Fix(es):

  * ipmitool: Buffer overflow in read_fru_area_section function in
lib/ipmi_fru.c (CVE-2020-5208)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'ipmitool' package(s) on CentOS 6." );
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
	if(!isnull( res = isrpmvuln( pkg: "ipmitool", rpm: "ipmitool~1.8.15~3.el6_10", rls: "CentOS6" ) )){
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

