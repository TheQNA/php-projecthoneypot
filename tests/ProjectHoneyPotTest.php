<?php

declare(strict_types=1);

namespace joshtronic\Tests;

use Exception;
use joshtronic\ProjectHoneyPot;
use PHPUnit\Framework\TestCase;

class ProjectHoneyPotTest extends TestCase
{
    public function testInvalidKey()
    {
        try {
            new ProjectHoneyPot('foo');
        } catch (Exception $e) {
            static::assertSame('You must specify a valid API key.', $e->getMessage());
        }
    }

    public function testInvalidIP()
    {
        $object = new ProjectHoneyPot('foobarfoobar');

        static::assertSame(
            ['error' => 'Invalid IP address.'],
            $object->query('foo'),
        );
    }

    public function testMissingResults()
    {
        $mock = $this->getMockBuilder('joshtronic\\ProjectHoneyPot')
            ->setConstructorArgs(['foobarfoobar'])
            ->setMethods(['dns_get_record'])
            ->getMock();

        $mock->expects(static::once())
            ->method('dns_get_record')
            ->willReturn('foo');

        static::assertFalse($mock->query('1.2.3.4'));
    }

    public function testCategory0()
    {
        $mock = $this->getMockBuilder('joshtronic\\ProjectHoneyPot')
            ->setConstructorArgs(['foobarfoobar'])
            ->setMethods(['dns_get_record'])
            ->getMock();

        $mock->expects(static::once())
            ->method('dns_get_record')
            ->willReturn([['ip' => '127.0.0.0']]);

        $results = $mock->query('1.2.3.4');

        static::assertSame(['Search Engine'], $results['categories']);
    }

    public function testCategory1()
    {
        $mock = $this->getMockBuilder('joshtronic\\ProjectHoneyPot')
            ->setConstructorArgs(['foobarfoobar'])
            ->setMethods(['dns_get_record'])
            ->getMock();

        $mock->expects(static::once())
            ->method('dns_get_record')
            ->willReturn([['ip' => '127.0.0.1']]);

        $results = $mock->query('1.2.3.4');

        static::assertSame(['Suspicious'], $results['categories']);
    }

    public function testCategory2()
    {
        $mock = $this->getMockBuilder('joshtronic\\ProjectHoneyPot')
            ->setConstructorArgs(['foobarfoobar'])
            ->setMethods(['dns_get_record'])
            ->getMock();

        $mock->expects(static::once())
            ->method('dns_get_record')
            ->willReturn([['ip' => '127.0.0.2']]);

        $results = $mock->query('1.2.3.4');

        static::assertSame(['Harvester'], $results['categories']);
    }

    public function testCategory3()
    {
        $mock = $this->getMockBuilder('joshtronic\\ProjectHoneyPot')
            ->setConstructorArgs(['foobarfoobar'])
            ->setMethods(['dns_get_record'])
            ->getMock();

        $mock->expects(static::once())
            ->method('dns_get_record')
            ->willReturn([['ip' => '127.0.0.3']]);

        $results = $mock->query('1.2.3.4');

        static::assertSame(
            ['Suspicious', 'Harvester'],
            $results['categories'],
        );
    }

    public function testCategory4()
    {
        $mock = $this->getMockBuilder('joshtronic\\ProjectHoneyPot')
            ->setConstructorArgs(['foobarfoobar'])
            ->setMethods(['dns_get_record'])
            ->getMock();

        $mock->expects(static::once())
            ->method('dns_get_record')
            ->willReturn([['ip' => '127.0.0.4']]);

        $results = $mock->query('1.2.3.4');

        static::assertSame(
            ['Comment Spammer'],
            $results['categories'],
        );
    }

    public function testCategory5()
    {
        $mock = $this->getMockBuilder('joshtronic\\ProjectHoneyPot')
            ->setConstructorArgs(['foobarfoobar'])
            ->setMethods(['dns_get_record'])
            ->getMock();

        $mock->expects(static::once())
            ->method('dns_get_record')
            ->willReturn([['ip' => '127.0.0.5']]);

        $results = $mock->query('1.2.3.4');

        static::assertSame(
            ['Suspicious', 'Comment Spammer'],
            $results['categories'],
        );
    }

    public function testCategory6()
    {
        $mock = $this->getMockBuilder('joshtronic\\ProjectHoneyPot')
            ->setConstructorArgs(['foobarfoobar'])
            ->setMethods(['dns_get_record'])
            ->getMock();

        $mock->expects(static::once())
            ->method('dns_get_record')
            ->willReturn([['ip' => '127.0.0.6']]);

        $results = $mock->query('1.2.3.4');

        static::assertSame(
            ['Harvester', 'Comment Spammer'],
            $results['categories'],
        );
    }

    public function testCategory7()
    {
        $mock = $this->getMockBuilder('joshtronic\\ProjectHoneyPot')
            ->setConstructorArgs(['foobarfoobar'])
            ->setMethods(['dns_get_record'])
            ->getMock();

        $mock->expects(static::once())
            ->method('dns_get_record')
            ->willReturn([['ip' => '127.0.0.7']]);

        $results = $mock->query('1.2.3.4');

        static::assertSame(
            ['Suspicious', 'Harvester', 'Comment Spammer'],
            $results['categories'],
        );
    }

    public function testCategoryDefault()
    {
        $mock = $this->getMockBuilder('joshtronic\\ProjectHoneyPot')
            ->setConstructorArgs(['foobarfoobar'])
            ->setMethods(['dns_get_record'])
            ->getMock();

        $mock->expects(static::once())
            ->method('dns_get_record')
            ->willReturn([['ip' => '127.0.0.255']]);

        $results = $mock->query('1.2.3.4');

        static::assertSame(
            ['Reserved for Future Use'],
            $results['categories'],
        );
    }

    public function testWithout127()
    {
        $mock = $this->getMockBuilder('joshtronic\\ProjectHoneyPot')
            ->setConstructorArgs(['foobarfoobar'])
            ->setMethods(['dns_get_record'])
            ->getMock();

        $mock->expects(static::once())
            ->method('dns_get_record')
            ->willReturn([['ip' => '1.0.0.0']]);

        static::assertFalse($mock->query('1.2.3.4'));
    }

    // Doesn't serve much purpose aside from helping achieve 100% coverage
    public function testDnsGetRecord()
    {
        $object = new ProjectHoneyPot('foobarfoobar');

        $result = $object->dns_get_record('1.2.3.4');

        static::assertSame([], $result);
    }
}
