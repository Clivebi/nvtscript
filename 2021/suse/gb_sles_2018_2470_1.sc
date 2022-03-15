if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2470.1" );
	script_cve_id( "CVE-2017-2862", "CVE-2017-2870", "CVE-2017-6312", "CVE-2017-6313", "CVE-2017-6314" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:38 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-08 02:29:00 +0000 (Wed, 08 Nov 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2470-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2470-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182470-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gtk2' package(s) announced via the SUSE-SU-2018:2470-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gtk2 provides the following fixes:
These security issues were fixed:
- CVE-2017-6312: Prevent integer overflow that allowed context-dependent
 attackers to cause a denial of service (segmentation fault and
 application crash) via a crafted image entry offset in an ICO file
 (bsc#1027026).
- CVE-2017-6314: The make_available_at_least function allowed
 context-dependent attackers to cause a denial of service (infinite loop)
 via a large TIFF file (bsc#1027025).
- CVE-2017-6313: Prevent integer underflow in the load_resources function
 that allowed context-dependent attackers to cause a denial of service
 (out-of-bounds read and program crash) via a crafted image entry size in
 an ICO file (bsc#1027024).
- CVE-2017-2862: Prevent heap overflow in the
 gdk_pixbuf__jpeg_image_load_increment function. A specially crafted jpeg
 file could have caused a heap overflow resulting in remote code
 execution (bsc#1048289)
- CVE-2017-2870: Prevent integer overflow in the tiff_image_parse
 functionality. A specially crafted tiff file could have caused a
 heap-overflow resulting in remote code execution (bsc#1048544).
This non-security issue was fixed:
- Prevent an infinite loop when a window is destroyed while traversed
 (bsc#1039465)." );
	script_tag( name: "affected", value: "'gtk2' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "gtk2", rpm: "gtk2~2.18.9~0.45.8.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gtk2-32bit", rpm: "gtk2-32bit~2.18.9~0.45.8.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gtk2-doc", rpm: "gtk2-doc~2.18.9~0.45.8.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gtk2-lang", rpm: "gtk2-lang~2.18.9~0.45.8.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gtk2-x86", rpm: "gtk2-x86~2.18.9~0.45.8.1", rls: "SLES11.0SP4" ) )){
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

