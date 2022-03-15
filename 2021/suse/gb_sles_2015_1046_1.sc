if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1046.1" );
	script_cve_id( "CVE-2015-3811", "CVE-2015-3812", "CVE-2015-3813", "CVE-2015-3814" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1046-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1046-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151046-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2015:1046-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Wireshark was updated to 1.10.14 to fix four security issues.
The following vulnerabilities have been fixed:
* CVE-2015-3811: The WCP dissector could crash while decompressing data.
 (wnpa-sec-2015-14)
* CVE-2015-3812: The X11 dissector could leak memory. (wnpa-sec-2015-15)
* CVE-2015-3813: The packet reassembly code could leak memory.
 (wnpa-sec-2015-16)
* CVE-2015-3814: The IEEE 802.11 dissector could go into an infinite loop.
 (wnpa-sec-2015-17)" );
	script_tag( name: "affected", value: "'wireshark' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~1.10.14~12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-debuginfo", rpm: "wireshark-debuginfo~1.10.14~12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-debugsource", rpm: "wireshark-debugsource~1.10.14~12.1", rls: "SLES12.0" ) )){
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

