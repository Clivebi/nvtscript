if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0258.1" );
	script_cve_id( "CVE-2020-27827" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:45 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-13 13:15:00 +0000 (Tue, 13 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0258-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0258-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210258-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openvswitch' package(s) announced via the SUSE-SU-2021:0258-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openvswitch fixes the following issues:

openvswitch was updated to 2.13.2

CVE-2020-27827: Fixed a memory leak when parsing lldp packets
 (bsc#1181345)" );
	script_tag( name: "affected", value: "'openvswitch' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2, SUSE Linux Enterprise Module for Server Applications 15-SP2." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libopenvswitch-2_13-0", rpm: "libopenvswitch-2_13-0~2.13.2~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenvswitch-2_13-0-debuginfo", rpm: "libopenvswitch-2_13-0-debuginfo~2.13.2~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvswitch-debuginfo", rpm: "openvswitch-debuginfo~2.13.2~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvswitch-debugsource", rpm: "openvswitch-debugsource~2.13.2~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-ovs", rpm: "python3-ovs~2.13.2~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libovn-20_03-0", rpm: "libovn-20_03-0~20.03.1~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libovn-20_03-0-debuginfo", rpm: "libovn-20_03-0-debuginfo~20.03.1~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvswitch", rpm: "openvswitch~2.13.2~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvswitch-devel", rpm: "openvswitch-devel~2.13.2~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvswitch-ipsec", rpm: "openvswitch-ipsec~2.13.2~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvswitch-pki", rpm: "openvswitch-pki~2.13.2~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvswitch-test", rpm: "openvswitch-test~2.13.2~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvswitch-test-debuginfo", rpm: "openvswitch-test-debuginfo~2.13.2~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvswitch-vtep", rpm: "openvswitch-vtep~2.13.2~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvswitch-vtep-debuginfo", rpm: "openvswitch-vtep-debuginfo~2.13.2~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ovn", rpm: "ovn~20.03.1~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ovn-central", rpm: "ovn-central~20.03.1~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ovn-devel", rpm: "ovn-devel~20.03.1~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ovn-docker", rpm: "ovn-docker~20.03.1~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ovn-host", rpm: "ovn-host~20.03.1~9.11.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ovn-vtep", rpm: "ovn-vtep~20.03.1~9.11.1", rls: "SLES15.0SP2" ) )){
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

