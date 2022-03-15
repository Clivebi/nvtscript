if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.1005.1" );
	script_cve_id( "CVE-2012-3571", "CVE-2012-3954" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-01 13:58:00 +0000 (Wed, 01 Apr 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:1005-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:1005-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20121005-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dhcp' package(s) announced via the SUSE-SU-2012:1005-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update of dhcp fixed two security vulnerabilities:

 * Malformed client identifiers could cause a Denial of Service (excessive CPU consumption), effectively causing further client requests to not be processed anymore.
(CVE-2012-3571
> )
 * Two unspecified memory leaks. (CVE-2012-3954
> )" );
	script_tag( name: "affected", value: "'dhcp' package(s) on SLE SDK 10 SP4, SUSE Linux Enterprise Desktop 10 SP4, SUSE Linux Enterprise Server 10 SP4." );
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "dhcp", rpm: "dhcp~3.0.7~7.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-client", rpm: "dhcp-client~3.0.7~7.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-devel", rpm: "dhcp-devel~3.0.7~7.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-relay", rpm: "dhcp-relay~3.0.7~7.17.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dhcp-server", rpm: "dhcp-server~3.0.7~7.17.1", rls: "SLES10.0SP4" ) )){
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

