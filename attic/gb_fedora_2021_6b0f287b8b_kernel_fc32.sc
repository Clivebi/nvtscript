if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818202" );
	script_version( "2021-09-20T14:50:00+0000" );
	script_cve_id( "CVE-2021-29646", "CVE-2021-29647", "CVE-2021-29648", "CVE-2021-29649", "CVE-2021-29650" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 14:50:00 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-05 12:24:00 +0000 (Mon, 05 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-02 03:05:32 +0000 (Fri, 02 Apr 2021)" );
	script_name( "Fedora: Security Advisory for kernel (FEDORA-2021-6b0f287b8b)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-6b0f287b8b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RZGMUP6QEHJJEKPMLKOSPWYMW7PXFC2M" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the FEDORA-2021-6b0f287b8b advisory.

  This VT has been deprecated and is therefore no longer functional." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The kernel meta package" );
	script_tag( name: "affected", value: "'kernel' package(s) on Fedora 32." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

