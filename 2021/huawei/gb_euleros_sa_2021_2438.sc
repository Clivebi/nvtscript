if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2438" );
	script_cve_id( "CVE-2019-10894", "CVE-2019-10895", "CVE-2019-10899", "CVE-2019-10901", "CVE-2019-10903" );
	script_tag( name: "creation_date", value: "2021-09-15 02:24:22 +0000 (Wed, 15 Sep 2021)" );
	script_version( "2021-09-15T02:24:22+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 02:24:22 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for wireshark (EulerOS-SA-2021-2438)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2438" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2438" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'wireshark' package(s) announced via the EulerOS-SA-2021-2438 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In Wireshark 2.4.0 to 2.4.13, 2.6.0 to 2.6.7, and 3.0.0, the LDSS dissector could crash. This was addressed in epan/dissectors/packet-ldss.c by handling file digests properly.(CVE-2019-10901)

In Wireshark 2.4.0 to 2.4.13, 2.6.0 to 2.6.7, and 3.0.0, the GSS-API dissector could crash. This was addressed in epan/dissectors/packet-gssapi.c by ensuring that a valid dissector is called.(CVE-2019-10894)

In Wireshark 2.4.0 to 2.4.13, 2.6.0 to 2.6.7, and 3.0.0, the NetScaler file parser could crash. This was addressed in wiretap etscaler.c by improving data validation.(CVE-2019-10895)

In Wireshark 2.4.0 to 2.4.13, 2.6.0 to 2.6.7, and 3.0.0, the SRVLOC dissector could crash. This was addressed in epan/dissectors/packet-srvloc.c by preventing a heap-based buffer under-read.(CVE-2019-10899)

In Wireshark 2.4.0 to 2.4.13, 2.6.0 to 2.6.7, and 3.0.0, the DCERPC SPOOLSS dissector could crash. This was addressed in epan/dissectors/packet-dcerpc-spoolss.c by adding a boundary check.(CVE-2019-10903)" );
	script_tag( name: "affected", value: "'wireshark' package(s) on Huawei EulerOS V2.0SP2." );
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
if(release == "EULEROS-2.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~1.10.14~7.h13", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-gnome", rpm: "wireshark-gnome~1.10.14~7.h13", rls: "EULEROS-2.0SP2" ) )){
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
