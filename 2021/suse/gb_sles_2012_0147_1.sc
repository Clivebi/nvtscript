if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.0147.1" );
	script_cve_id( "CVE-2011-2686", "CVE-2011-2705", "CVE-2011-3009", "CVE-2011-4815" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-29 01:30:00 +0000 (Tue, 29 Aug 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:0147-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:0147-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20120147-1/" );
	script_xref( name: "URL", value: "http://svn.ruby-lang.org/repos/ruby/tags/v1_8_7_357/ChangeLo" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby' package(s) announced via the SUSE-SU-2012:0147-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update of ruby provides 1.8.7p357, which contains many stability fixes and bug fixes while maintaining full compatibility with the previous version. A detailailed list of changes is available from [link moved to references] g og> .

The most important fixes are:

 * Hash functions are now using a randomized seed to avoid algorithmic complexity attacks. If available,
OpenSSL::Random.seed at the SecureRandom.random_bytes is used to achieve this. (CVE-2011-4815
> )
 * mkconfig.rb: fix for continued lines.
 * Fix Infinity to be greater than any bignum number.
 * Initialize store->ex_data.sk.
 * Several IPv6 related fixes.
 * Fixes for zlib.
 * Reinitialize PRNG when forking children
(CVE-2011-2686
> , CVE-2011-3009
> )
 * Fixes to securerandom. (CVE-2011-2705
> )
 * Fix uri route_to
 * Fix race condition with variables and autoload." );
	script_tag( name: "affected", value: "'ruby' package(s) on SUSE Lifecycle Management Server 1.1, SUSE Linux Enterprise Desktop 11 SP1, SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Software Development Kit 11 SP1, SUSE Studio Extension for System z 1.2, SUSE Studio Onsite 1.1, SUSE Studio Onsite 1.2, SUSE Studio Standard Edition 1.2, WebYaST 1.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "ruby", rpm: "ruby~1.8.7.p357~0.7.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-doc-html", rpm: "ruby-doc-html~1.8.7.p357~0.7.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-tk", rpm: "ruby-tk~1.8.7.p357~0.7.1", rls: "SLES11.0SP1" ) )){
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

