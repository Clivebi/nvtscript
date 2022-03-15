if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.0981.1" );
	script_cve_id( "CVE-2018-9256", "CVE-2018-9259", "CVE-2018-9260", "CVE-2018-9261", "CVE-2018-9262", "CVE-2018-9263", "CVE-2018-9264", "CVE-2018-9265", "CVE-2018-9266", "CVE-2018-9267", "CVE-2018-9268", "CVE-2018-9269", "CVE-2018-9270", "CVE-2018-9271", "CVE-2018-9272", "CVE-2018-9273", "CVE-2018-9274" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-27 17:14:00 +0000 (Wed, 27 Feb 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:0981-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:0981-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20180981-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2018:0981-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for wireshark fixes the following issues:
- Update to wireshark 2.2.14, fix such issues:
 * bsc#1088200 VUL-0: wireshark: multiple vulnerabilities fixed in
 2.2.14, 2.4.6
 * CVE-2018-9256: LWAPP dissector crash
 * CVE-2018-9260: IEEE 802.15.4 dissector crash
 * CVE-2018-9261: NBAP dissector crash
 * CVE-2018-9262: VLAN dissector crash
 * CVE-2018-9263: Kerberos dissector crash
 * CVE-2018-9264: ADB dissector crash
 * CVE-2018-9265: tn3270 dissector has a memory leak
 * CVE-2018-9266: ISUP dissector memory leak
 * CVE-2018-9267: LAPD dissector memory leak
 * CVE-2018-9268: SMB2 dissector memory leak
 * CVE-2018-9269: GIOP dissector memory leak
 * CVE-2018-9270: OIDS dissector memory leak
 * CVE-2018-9271: multipart dissector memory leak
 * CVE-2018-9272: h223 dissector memory leak
 * CVE-2018-9273: pcp dissector memory leak
 * CVE-2018-9274: failure message memory leak
 * CVE-2018-9259: MP4 dissector crash" );
	script_tag( name: "affected", value: "'wireshark' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libwireshark8", rpm: "libwireshark8~2.2.14~48.24.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwireshark8-debuginfo", rpm: "libwireshark8-debuginfo~2.2.14~48.24.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwiretap6", rpm: "libwiretap6~2.2.14~48.24.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwiretap6-debuginfo", rpm: "libwiretap6-debuginfo~2.2.14~48.24.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwscodecs1", rpm: "libwscodecs1~2.2.14~48.24.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwscodecs1-debuginfo", rpm: "libwscodecs1-debuginfo~2.2.14~48.24.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwsutil7", rpm: "libwsutil7~2.2.14~48.24.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwsutil7-debuginfo", rpm: "libwsutil7-debuginfo~2.2.14~48.24.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~2.2.14~48.24.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-debuginfo", rpm: "wireshark-debuginfo~2.2.14~48.24.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-debugsource", rpm: "wireshark-debugsource~2.2.14~48.24.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-gtk", rpm: "wireshark-gtk~2.2.14~48.24.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-gtk-debuginfo", rpm: "wireshark-gtk-debuginfo~2.2.14~48.24.1", rls: "SLES12.0SP3" ) )){
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

