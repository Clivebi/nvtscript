if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.0261.1" );
	script_cve_id( "CVE-2012-0452" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-10 02:29:00 +0000 (Wed, 10 Jan 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:0261-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:0261-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20120261-1/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/security/announce/2012/mfsa2012-10.h" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2012:0261-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MozillaFirefox was updated to 10.0.1 to fix critical bugs and security issue.

The following security issue has been fixed:

CVE-2012-0452: Mozilla developers Andrew McCreight and Olli Pettay found that ReadPrototypeBindings will leave a XBL binding in a hash table even when the function fails. If this occurs, when the cycle collector reads this hash table and attempts to do a virtual method on this binding a crash will occur. This crash may be potentially exploitable.

Firefox 9 and earlier are not affected by this vulnerability.

[link moved to references] tml html>

Security Issues:

 * CVE-2012-0452
>" );
	script_tag( name: "affected", value: "'Mozilla Firefox' package(s) on SUSE Linux Enterprise Desktop 11 SP1, SUSE Linux Enterprise Server 11 SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~10.0.1~0.4.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~10.0.1~0.4.1", rls: "SLES11.0SP1" ) )){
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

