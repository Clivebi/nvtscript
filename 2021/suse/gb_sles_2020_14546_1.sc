if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.14546.1" );
	script_cve_id( "CVE-2020-8695", "CVE-2020-8696", "CVE-2020-8698" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:49 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-11 19:28:00 +0000 (Thu, 11 Feb 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:14546-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:14546-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-202014546-1/" );
	script_xref( name: "URL", value: "https://www.intel.com/content/www/us/en/security-center/ad" );
	script_xref( name: "URL", value: "https://www.intel.com/content/www/us/en/security-center/ad" );
	script_xref( name: "URL", value: "https://cdrdv2.intel.com/v1/dl/getContent/338848" );
	script_xref( name: "URL", value: "https://cdrdv2.intel.com/v1/dl/getContent/613537" );
	script_xref( name: "URL", value: "https://www.intel.com/content/www/us/en/processors/xeon/xeon-e5-v3-" );
	script_xref( name: "URL", value: "https://www.intel.com/content/www/us/en/products/docs/processors/co" );
	script_xref( name: "URL", value: "https://www.intel.com/content/www/us/en/products/docs/processors/co" );
	script_xref( name: "URL", value: "https://www.intel.com/content/www/us/en/processors/core/7th-gen-cor" );
	script_xref( name: "URL", value: "https://cdrdv2.intel.com/v1/dl/getContent/332689" );
	script_xref( name: "URL", value: "https://www.intel.com/content/www/us/en/processors/xeon/xeon-e3-120" );
	script_xref( name: "URL", value: "https://www.intel.com/content/www/us/en/products/docs/processors/xe" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'microcode_ctl' package(s) announced via the SUSE-SU-2020:14546-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for microcode_ctl fixes the following issues:

Updated Intel CPU Microcode to 20201110 official release.
 - CVE-2020-8695: Fixed Intel RAPL sidechannel attack (SGX) INTEL-SA-00389
 (bsc#1170446)
 - CVE-2020-8698: Fixed Fast Store Forward Predictor INTEL-SA-00381
 (bsc#1173594)
 - CVE-2020-8696: Vector Register Sampling Active INTEL-SA-00381
 (bsc#1173592)

Release notes:
 - Security updates for
[INTEL-SA-00381]([link moved to references]
 visory/intel-sa-00381.html).
 - Security updates for
[INTEL-SA-00389]([link moved to references]
 visory/intel-sa-00389.html).
 - Update for functional issues. Refer to [Second Generation Intel(r)
 Xeon(r) Processor Scalable Family Specification
 Update]([link moved to references]) for details.
 - Update for functional issues. Refer to [Intel(r) Xeon(r) Processor
 Scalable Family Specification
 Update]([link moved to references]) for details.
 - Update for functional issues. Refer to [Intel(r) Xeon(r) Processor E5 v3
 Product Family Specification Update]([link moved to references]
 spec-update.html?wapkw=processor+spec+update+e5) for details.
 - Update for functional issues. Refer to [10th Gen Intel(r) Core(tm)
 Processor Families Specification Update]([link moved to references]
 re/10th-gen-core-families-specification-update.html) for details.
 - Update for functional issues. Refer to [8th and 9th Gen Intel(r)
 Core(tm) Processor Family Spec Update]([link moved to references]
 re/8th-gen-core-spec-update.html) for details.
 - Update for functional issues. Refer to [7th Gen and 8th Gen (U
 Quad-Core) Intel(r) Processor Families Specification Update]([link moved to references]
 e-family-spec-update.html) for details.
 - Update for functional issues. Refer to [6th Gen Intel(r) Processor
 Family Specification
 Update]([link moved to references]) for details.
 - Update for functional issues. Refer to [Intel(r) Xeon(r) E3-1200 v6
 Processor Family Specification Update]([link moved to references]
 0v6-spec-update.html) for details.
 - Update for functional issues. Refer to [Intel(r) Xeon(r) E-2100 and
 E-2200 Processor Family Specification Update]([link moved to references]
 on/xeon-e-2100-specification-update.html) for details.

 ### New Platforms <pipe> Processor <pipe> Stepping <pipe> F-M-S/PI <pipe> Old Ver <pipe>
New Ver <pipe> Products
<pipe>:---------------<pipe>:---------<pipe>:------------<pipe>:---------<pipe>:---------<pipe>:---------
 <pipe> CPX-SP <pipe> A1 <pipe> 06-55-0b/bf <pipe> <pipe> 0700001e <pipe> Xeon Scalable Gen3 <pipe> LKF <pipe> B2/B3 ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'microcode_ctl' package(s) on SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "microcode_ctl", rpm: "microcode_ctl~1.17~102.83.62.1", rls: "SLES11.0SP4" ) )){
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

