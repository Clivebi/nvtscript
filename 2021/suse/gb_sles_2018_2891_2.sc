if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2891.2" );
	script_cve_id( "CVE-2018-11354", "CVE-2018-11355", "CVE-2018-11356", "CVE-2018-11357", "CVE-2018-11358", "CVE-2018-11359", "CVE-2018-11360", "CVE-2018-11361", "CVE-2018-11362", "CVE-2018-14339", "CVE-2018-14340", "CVE-2018-14341", "CVE-2018-14342", "CVE-2018-14343", "CVE-2018-14344", "CVE-2018-14367", "CVE-2018-14368", "CVE-2018-14369", "CVE-2018-14370", "CVE-2018-16056", "CVE-2018-16057", "CVE-2018-16058" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-20 01:15:00 +0000 (Fri, 20 Mar 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2891-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2891-2" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182891-2/" );
	script_xref( name: "URL", value: "https://www.wireshark.org/docs/relnotes/wireshark-2.4.9.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2018:2891-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for wireshark to version 2.4.9 fixes the following issues:

Wireshark was updated to 2.4.9 (bsc#1094301, bsc#1106514).

Security issues fixed:
CVE-2018-16058: Bluetooth AVDTP dissector crash (wnpa-sec-2018-44)

CVE-2018-16056: Bluetooth Attribute Protocol dissector crash
 (wnpa-sec-2018-45)

CVE-2018-16057: Radiotap dissector crash (wnpa-sec-2018-46)

CVE-2018-11355: Fix RTCP dissector crash (bsc#1094301).

CVE-2018-14370: IEEE 802.11 dissector crash (wnpa-sec-2018-43,
 bsc#1101802)

CVE-2018-14368: Bazaar dissector infinite loop (wnpa-sec-2018-40,
 bsc#1101794)

CVE-2018-11362: Fix LDSS dissector crash (bsc#1094301).

CVE-2018-11361: Fix IEEE 802.11 dissector crash (bsc#1094301).

CVE-2018-11360: Fix GSM A DTAP dissector crash (bsc#1094301).

CVE-2018-14342: BGP dissector large loop (wnpa-sec-2018-34, bsc#1101777)

CVE-2018-14343: ASN.1 BER dissector crash (wnpa-sec-2018-37, bsc#1101786)

CVE-2018-14340: Multiple dissectors could crash (wnpa-sec-2018-36,
 bsc#1101804)

CVE-2018-14341: DICOM dissector crash (wnpa-sec-2018-39, bsc#1101776)

CVE-2018-11358: Fix Q.931 dissector crash (bsc#1094301).

CVE-2018-14344: ISMP dissector crash (wnpa-sec-2018-35, bsc#1101788)

CVE-2018-11359: Fix multiple dissectors crashs (bsc#1094301).

CVE-2018-11356: Fix DNS dissector crash (bsc#1094301).

CVE-2018-14339: MMSE dissector infinite loop (wnpa-sec-2018-38,
 bsc#1101810)

CVE-2018-11357: Fix multiple dissectors that could consume excessive
 memory (bsc#1094301).

CVE-2018-14367: CoAP dissector crash (wnpa-sec-2018-42, bsc#1101791)

CVE-2018-11354: Fix IEEE 1905.1a dissector crash (bsc#1094301).

CVE-2018-14369: HTTP2 dissector crash (wnpa-sec-2018-41, bsc#1101800)

Further bug fixes and updated protocol support as listed in:
[link moved to references]" );
	script_tag( name: "affected", value: "'wireshark' package(s) on SUSE Linux Enterprise Server 12-SP2." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libwireshark9", rpm: "libwireshark9~2.4.9~48.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwireshark9-debuginfo", rpm: "libwireshark9-debuginfo~2.4.9~48.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwiretap7", rpm: "libwiretap7~2.4.9~48.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwiretap7-debuginfo", rpm: "libwiretap7-debuginfo~2.4.9~48.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwscodecs1", rpm: "libwscodecs1~2.4.9~48.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwscodecs1-debuginfo", rpm: "libwscodecs1-debuginfo~2.4.9~48.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwsutil8", rpm: "libwsutil8~2.4.9~48.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwsutil8-debuginfo", rpm: "libwsutil8-debuginfo~2.4.9~48.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~2.4.9~48.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-debuginfo", rpm: "wireshark-debuginfo~2.4.9~48.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-debugsource", rpm: "wireshark-debugsource~2.4.9~48.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-gtk", rpm: "wireshark-gtk~2.4.9~48.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-gtk-debuginfo", rpm: "wireshark-gtk-debuginfo~2.4.9~48.29.1", rls: "SLES12.0SP2" ) )){
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

