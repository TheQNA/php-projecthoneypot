<?php

declare(strict_types=1);

namespace joshtronic;

use Exception;

class ProjectHoneyPot
{
    /**
     * API Key.
     *
     * @var string
     */
    private $api_key = '';

    /**
     * Constructor.
     *
     * Adds the specified API key to the object.
     *
     * @param string $api_key PHP API Key (12 characters)
     */
    public function __construct($api_key)
    {
        if (preg_match('/^[a-z]{12}$/', $api_key)) {
            $this->api_key = $api_key;
        } else {
            throw new Exception('You must specify a valid API key.');
        }
    }

    /**
     * Query.
     *
     * Performs a DNS lookup to obtain information about the IP address.
     *
     * @param string $ip_address IPv4 address to check
     *
     * @return array results from query
     */
    public function query($ip_address)
    {
        // Validates the IP format
        if (filter_var($ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE)) {
            // Flips the script, err, IP address
            $octets = explode('.', $ip_address);
            krsort($octets);
            $reversed_ip = implode('.', $octets);

            // Performs the query
            $results = $this->dns_get_record($reversed_ip);

            // Processes the results
            if (isset($results[0]['ip'])) {
                $results = explode('.', $results[0]['ip']);

                if ($results[0] == 127) {
                    $results = [
                        'categories' => (int) $results[3],
                        'threat_score' => $results[2],
                        'last_activity' => $results[1] . ' day(s) ago',
                    ];

                    $categories = match ($results['categories']) {
                        0 => ['Search Engine'],
                        1 => ['Suspicious'],
                        2 => ['Harvester'],
                        3 => ['Suspicious', 'Harvester'],
                        4 => ['Comment Spammer'],
                        5 => ['Suspicious', 'Comment Spammer'],
                        6 => ['Harvester', 'Comment Spammer'],
                        7 => ['Suspicious', 'Harvester', 'Comment Spammer'],
                        default => ['Unknown'],
                    };

                    $results['categories'] = $categories;

                    return $results;
                }
            }
        } else {
            return ['error' => 'Invalid IP address.'];
        }

        return false;
    }

    /**
     * DNS Get Record.
     *
     * Wrapper method for dns_get_record() to allow for easy mocking of the
     * results in our tests. Takes an already reversed IP address and does a
     * DNS lookup for A records against the http:BL API.
     *
     * @param string $reversed_ip reversed IPv4 address to check
     *
     * @return array results from the DNS lookup
     */
    public function dns_get_record($reversed_ip)
    {
        return dns_get_record($this->api_key . '.' . $reversed_ip . '.dnsbl.httpbl.org', DNS_A);
    }
}
