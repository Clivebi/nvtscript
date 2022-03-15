if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.0743.1" );
	script_cve_id( "CVE-2012-5134", "CVE-2013-0338", "CVE-2013-0339" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-29 01:32:00 +0000 (Tue, 29 Aug 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:0743-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:0743-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20130743-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxml2' package(s) announced via the SUSE-SU-2013:0743-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "libxml2 has been updated to fix two security bugs.

 * CVE-2013-0338: Internal entity expansion within XML was not bounded, leading to simple small XML files being able to cause 'out of memory' denial of service conditions.
 * CVE-2012-5134: Heap-based buffer underflow in the xmlParseAttValueComplex function in parser.c in libxml2 allowed remote attackers to cause a denial of service or possibly execute arbitrary code via crafted entities in an XML document.

Security Issue references:

 * CVE-2013-0338
>
 * CVE-2013-0339
>" );
	script_tag( name: "affected", value: "'libxml2' package(s) on SUSE Linux Enterprise Server 11 SP1." );
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libxml2", rpm: "libxml2~2.7.6~0.23.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-32bit", rpm: "libxml2-32bit~2.7.6~0.23.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-doc", rpm: "libxml2-doc~2.7.6~0.23.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-python", rpm: "libxml2-python~2.7.6~0.23.1", rls: "SLES11.0SP1" ) )){
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

