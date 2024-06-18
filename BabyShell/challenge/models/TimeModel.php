<?php

class TimeModel
{
    public function __construct($format)
    {
        $this->format = $format;
    }

    public function getTime()
    {
        $time = date($this->format);
        return $time;
    }
}
