if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.1559.1" );
	script_cve_id( "CVE-2015-5260", "CVE-2015-5261", "CVE-2016-0749", "CVE-2016-2150" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-22 17:48:00 +0000 (Mon, 22 Apr 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:1559-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:1559-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20161559-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spice' package(s) announced via the SUSE-SU-2016:1559-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "spice was updated to fix four security issues.
These security issues were fixed:
- CVE-2016-2150: Guest escape using crafted primary surface parameters
 (bsc#982386).
- CVE-2016-0749: Heap-based buffer overflow in smartcard interaction
 (bsc#982385).
- CVE-2015-5260: Insufficient validation of surface_id parameter could
 have caused a crash (bsc#944787).
- CVE-2015-5261: Host memory access from guest using crafted images
 (bsc#948976)." );
	script_tag( name: "affected", value: "'spice' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libspice-server1", rpm: "libspice-server1~0.12.5~4.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspice-server1-debuginfo", rpm: "libspice-server1-debuginfo~0.12.5~4.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-debugsource", rpm: "spice-debugsource~0.12.5~4.1", rls: "SLES12.0SP1" ) )){
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

